/**
 * @fileoverview Verify Signature.unit.test (tests).
 *
 * - Test coverage for CBOR Viewer behaviors.
 * - Prefer intent-revealing fixtures and assertions over duplicating implementation details.
 * - Keep failures actionable: assert on user-visible output shapes when possible.
 */
import * as assert from 'assert';
import * as cbor from 'cbor';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import mockRequire from 'mock-require';

import { createVscodeMock } from './vscodeMock';
import { buildSigStructure, loadPublicKey, verifyCoseSignature } from '../../preview/extenders/verifySignature/coseVerify';
import { decodeVerifyTarget, encodeVerifyTarget, type CoseVerifyTarget } from '../../pretty/core/coseVerifyTarget';
import { decodeCborDecodedValueWithViews } from '../../cborDecoder';

const FIXTURES = path.resolve(__dirname, '../../../test/fixtures');

function enc(value: unknown): Buffer {
    const out = cbor.encodeOne(value as any);
    return Buffer.isBuffer(out) ? out : Buffer.from(out);
}

type Signer = (tbs: Buffer) => Buffer;

const keys = {
    ec: crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }),
    ed: crypto.generateKeyPairSync('ed25519'),
    rsa: crypto.generateKeyPairSync('rsa', { modulusLength: 2048 })
};

const signers: Record<string, { alg: number; pair: { publicKey: crypto.KeyObject }; sign: Signer }> = {
    ES256: { alg: -7, pair: keys.ec, sign: (t) => crypto.sign('sha256', t, { key: keys.ec.privateKey, dsaEncoding: 'ieee-p1363' }) },
    EdDSA: { alg: -8, pair: keys.ed, sign: (t) => crypto.sign(null, t, keys.ed.privateKey) },
    PS256: {
        alg: -37,
        pair: keys.rsa,
        sign: (t) => crypto.sign('sha256', t, { key: keys.rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 })
    },
    RS256: { alg: -257, pair: keys.rsa, sign: (t) => crypto.sign('sha256', t, keys.rsa.privateKey) }
};

function makeSign1(alg: number, sign: Signer, payload: Buffer, detached = false): { message: Buffer; target: CoseVerifyTarget } {
    const bodyProtected = enc(new Map([[1, alg]]));
    const target: CoseVerifyTarget = { context: 'Signature1', bodyProtected, signature: Buffer.alloc(0), alg };
    target.signature = sign(buildSigStructure(target, payload));
    const message = enc(new cbor.Tagged(18, [bodyProtected, new Map(), detached ? null : payload, target.signature]));
    return { message, target };
}

function writeTemp(name: string, content: string | Buffer): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cbor-verify-'));
    const file = path.join(dir, name);
    fs.writeFileSync(file, content);
    return file;
}

suite('Unit: COSE signature verification', () => {
    teardown(() => {
        mockRequire.stopAll();
    });

    test('real SCITT statement verifies with its x5chain leaf (DER and PEM)', () => {
        const root = cbor.decodeFirstSync(fs.readFileSync(path.join(FIXTURES, '2ts-statement.scitt.cose')));
        const [bodyProtected, , payload, signature] = root.value;
        const chain = cbor.decodeFirstSync(bodyProtected).get(33) as Buffer[];
        const target: CoseVerifyTarget = { context: 'Signature1', bodyProtected, signature, alg: -38 };

        assert.deepStrictEqual(verifyCoseSignature(target, payload, loadPublicKey(chain[0])), { valid: true, algorithm: 'PS384' });
        const pem = Buffer.from(new crypto.X509Certificate(chain[0]).toString());
        assert.strictEqual(verifyCoseSignature(target, payload, loadPublicKey(pem)).valid, true);
        assert.strictEqual(verifyCoseSignature(target, payload, loadPublicKey(chain[1])).valid, false);
    });

    test('verifies ES256 / EdDSA / PS256 / RS256 and rejects a tampered payload', () => {
        const payload = Buffer.from('hello cose');
        for (const [name, s] of Object.entries(signers)) {
            const { target } = makeSign1(s.alg, s.sign, payload);
            const pem = Buffer.from(s.pair.publicKey.export({ type: 'spki', format: 'pem' }) as string);
            assert.deepStrictEqual(verifyCoseSignature(target, payload, loadPublicKey(pem)), { valid: true, algorithm: name });
            assert.strictEqual(verifyCoseSignature(target, Buffer.from('tampered'), loadPublicKey(pem)).valid, false, name);
        }
    });

    test('COSE_Sign Sig_structure includes signer protected headers', () => {
        const payload = Buffer.from('multi');
        const target: CoseVerifyTarget = {
            context: 'Signature',
            bodyProtected: enc(new Map([[3, 0]])),
            signProtected: enc(new Map([[1, -7]])),
            signature: Buffer.alloc(0),
            alg: -7
        };
        const tbs = buildSigStructure(target, payload);
        assert.deepStrictEqual(cbor.decodeFirstSync(tbs), ['Signature', target.bodyProtected, target.signProtected, Buffer.alloc(0), payload]);
        target.signature = signers.ES256.sign(tbs);
        assert.strictEqual(verifyCoseSignature(target, payload, keys.ec.publicKey).valid, true);
    });

    test('verifyCoseSignature reports missing/unsupported alg and key type mismatch', () => {
        const base: CoseVerifyTarget = { context: 'Signature1', bodyProtected: Buffer.alloc(0), signature: Buffer.alloc(64) };
        assert.throws(() => verifyCoseSignature(base, Buffer.alloc(0), keys.ec.publicKey), /no "alg"/);
        assert.throws(() => verifyCoseSignature({ ...base, alg: 5 }, Buffer.alloc(0), keys.ec.publicKey), /Unsupported COSE algorithm 5/);
        assert.throws(() => verifyCoseSignature({ ...base, alg: -7 }, Buffer.alloc(0), keys.rsa.publicKey), /"rsa" cannot verify ES256/);
    });

    test('loadPublicKey accepts PEM, private PEM, DER SPKI, JWK and COSE_Key', () => {
        const ecJwk = keys.ec.privateKey.export({ format: 'jwk' }) as any;
        const edJwk = keys.ed.publicKey.export({ format: 'jwk' }) as any;
        const rsaJwk = keys.rsa.publicKey.export({ format: 'jwk' }) as any;
        const b = (s: string) => Buffer.from(s, 'base64url');

        const loaded = [
            loadPublicKey(Buffer.from(keys.ec.publicKey.export({ type: 'spki', format: 'pem' }) as string)),
            loadPublicKey(Buffer.from(keys.ec.privateKey.export({ type: 'pkcs8', format: 'pem' }) as string)),
            loadPublicKey(keys.ec.publicKey.export({ type: 'spki', format: 'der' })),
            loadPublicKey(Buffer.from(JSON.stringify(ecJwk))),
            loadPublicKey(enc(new Map<number, unknown>([[1, 2], [-1, 1], [-2, b(ecJwk.x)], [-3, b(ecJwk.y)]])))
        ];
        for (const k of loaded) {
            assert.strictEqual(k.type, 'public');
            assert.ok(k.equals(keys.ec.publicKey));
        }
        assert.ok(loadPublicKey(enc(new Map<number, unknown>([[1, 1], [-1, 6], [-2, b(edJwk.x)]]))).equals(keys.ed.publicKey));
        assert.ok(loadPublicKey(enc(new Map<number, unknown>([[1, 3], [-1, b(rsaJwk.n)], [-2, b(rsaJwk.e)]]))).equals(keys.rsa.publicKey));
    });

    test('loadPublicKey rejects malformed inputs with clear errors', () => {
        assert.throws(() => loadPublicKey(Buffer.from('{not json')), /could not be parsed/);
        assert.throws(() => loadPublicKey(Buffer.from([0x01, 0x02, 0x03])), /Unrecognized key format/);
        assert.throws(() => loadPublicKey(enc(new Map<number, unknown>([[1, 4]]))), /kty 4/);
        assert.throws(() => loadPublicKey(enc(new Map<number, unknown>([[1, 2], [-1, 99]]))), /curve 99/);
        assert.throws(() => loadPublicKey(enc(new Map<number, unknown>([[1, 1], [-1, 6], [-2, 'x']]))), /parameter -2/);
    });

    test('verify target round-trips and rejects malformed descriptors', () => {
        const target: CoseVerifyTarget = {
            context: 'Signature',
            bodyProtected: Buffer.from([0xa0]),
            signProtected: Buffer.from([0xa1, 0x01, 0x26]),
            payloadBlobId: 'blob-7',
            signature: Buffer.from([1, 2, 3]),
            alg: -7
        };
        assert.deepStrictEqual(decodeVerifyTarget(encodeVerifyTarget(target)), target);
        assert.deepStrictEqual(
            decodeVerifyTarget(encodeVerifyTarget({ context: 'Signature1', bodyProtected: Buffer.alloc(0), signature: Buffer.from([9]) })),
            { context: 'Signature1', bodyProtected: Buffer.alloc(0), signature: Buffer.from([9]) }
        );
        assert.strictEqual(decodeVerifyTarget(Buffer.from([0xff])), undefined);
        assert.strictEqual(decodeVerifyTarget(enc([1, 2])), undefined);
        assert.strictEqual(decodeVerifyTarget(enc(['Other', Buffer.alloc(0), null, null, Buffer.alloc(0), null])), undefined);
    });

    test('pretty view exposes a verify action for COSE_Sign1 and each COSE_Sign signer', () => {
        const payload = Buffer.from('payload');
        const sign1 = cbor.decodeFirstSync(makeSign1(-7, signers.ES256.sign, payload).message);
        const v1 = decodeCborDecodedValueWithViews(sign1, 0);
        const sig: any = (v1.pretty as any).signature;
        assert.strictEqual(sig.verify, 'Verify signature\u2026');
        assert.strictEqual(sig._previewHints.verify.kind, 'verifySig');
        const t1 = decodeVerifyTarget(v1.blobs.get(sig._previewHints.verify.blobId)!)!;
        assert.strictEqual(t1.alg, -7);
        assert.deepStrictEqual(v1.blobs.get(t1.payloadBlobId!), payload);

        const signTagged = new cbor.Tagged(98, [
            enc(new Map([[3, 0]])),
            new Map(),
            null,
            [[enc(new Map([[1, -8]])), new Map(), Buffer.alloc(64)], 'not-a-signer']
        ]);
        const v2 = decodeCborDecodedValueWithViews(signTagged, 0);
        const signer: any = (v2.pretty as any).signatures[0].signature;
        const t2 = decodeVerifyTarget(v2.blobs.get(signer._previewHints.verify.blobId)!)!;
        assert.strictEqual(t2.context, 'Signature');
        assert.strictEqual(t2.alg, -8);
        assert.strictEqual(t2.payloadBlobId, undefined);
        assert.strictEqual((v2.pretty as any).signature.verify, undefined);
    });

    test('verifySignature message handler: dialogs, results and error paths', async () => {
        const { vscode, state } = createVscodeMock();
        mockRequire('vscode', vscode);
        const { PreviewSystem } = mockRequire.reRequire('../../preview/previewSystem');
        const { previewExtender } = mockRequire.reRequire('../../preview/extenders/verifySignature/extender');
        const system = new PreviewSystem();
        previewExtender.register(system);
        assert.ok(system.getPreviewHintKinds().some((k: any) => k.kind === 'verifySig' && k.displayAsButton));

        const payload = Buffer.from('signed content');
        const attached = decodeCborDecodedValueWithViews(cbor.decodeFirstSync(makeSign1(-7, signers.ES256.sign, payload).message), 0);
        const detached = decodeCborDecodedValueWithViews(cbor.decodeFirstSync(makeSign1(-7, signers.ES256.sign, payload, true).message), 0);
        const attachedId = (attached.pretty as any).signature._previewHints.verify.blobId;
        const detachedId = (detached.pretty as any).signature._previewHints.verify.blobId;

        const goodKey = vscode.Uri.file(writeTemp('good.pem', keys.ec.publicKey.export({ type: 'spki', format: 'pem' }) as string));
        const otherKey = vscode.Uri.file(writeTemp('other.pem', crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ type: 'spki', format: 'pem' }) as string));
        const rsaKey = vscode.Uri.file(writeTemp('rsa.pem', keys.rsa.publicKey.export({ type: 'spki', format: 'pem' }) as string));
        const payloadFile = vscode.Uri.file(writeTemp('payload.bin', payload));

        const posted: any[] = [];
        const ctxFor = (blobs: Map<string, Buffer>) => ({ memFs: {} as any, blobs, postMessage: async (m: any) => { posted.push(m); return true; } });
        const run = (blobId: unknown, blobs: Map<string, Buffer>) =>
            system.handleWebviewMessage({ type: 'verifySignature', blobId }, ctxFor(blobs));

        // Missing blob id / unknown blob: silently handled.
        assert.strictEqual(await run(undefined, attached.blobs), true);
        assert.strictEqual(await run('missing', attached.blobs), true);
        assert.strictEqual(posted.length, 0);

        // Corrupt descriptor.
        assert.strictEqual(await run('bad', new Map([['bad', Buffer.from([0xff])]])), true);
        assert.strictEqual(posted.pop().status, 'error');

        // Key dialog cancelled.
        state.openDialogResults.push(undefined);
        assert.strictEqual(await run(attachedId, attached.blobs), true);
        assert.strictEqual(posted.length, 0);

        // Valid.
        state.openDialogResults.push([goodKey]);
        await run(attachedId, attached.blobs);
        assert.deepStrictEqual(posted.pop(), {
            type: 'verifySignatureResult',
            blobId: attachedId,
            status: 'valid',
            text: 'Signature is VALID (ES256, key: good.pem).',
            keyPath: goodKey.fsPath
        });
        assert.ok(state.infoMessages.some(m => m.includes('VALID (ES256, key: good.pem)')));

        // Invalid (different key).
        state.openDialogResults.push([otherKey]);
        await run(attachedId, attached.blobs);
        assert.strictEqual(posted.pop().status, 'invalid');
        assert.ok(state.errorMessages.some(m => m.includes('INVALID')));

        // Key type mismatch -> error.
        state.openDialogResults.push([rsaKey]);
        await run(attachedId, attached.blobs);
        const err = posted.pop();
        assert.strictEqual(err.status, 'error');
        assert.ok(err.text.includes('cannot verify ES256'));
        assert.strictEqual(err.keyPath, rsaKey.fsPath);

        // Embedded payload blob missing -> error.
        const noPayload = new Map(attached.blobs);
        noPayload.delete(decodeVerifyTarget(attached.blobs.get(attachedId)!)!.payloadBlobId!);
        state.openDialogResults.push([goodKey]);
        await run(attachedId, noPayload);
        assert.ok(posted.pop().text.includes('payload is not available'));

        // Detached payload: cancelled, then supplied.
        state.openDialogResults.push([goodKey], undefined);
        await run(detachedId, detached.blobs);
        assert.strictEqual(posted.length, 0);
        state.openDialogResults.push([goodKey], [payloadFile]);
        await run(detachedId, detached.blobs);
        assert.strictEqual(posted.pop().status, 'valid');

        // A failing postMessage (closed webview) is tolerated.
        state.openDialogResults.push([goodKey]);
        assert.strictEqual(
            await system.handleWebviewMessage(
                { type: 'verifySignature', blobId: attachedId },
                { memFs: {} as any, blobs: attached.blobs, postMessage: async () => { throw new Error('disposed'); } }
            ),
            true
        );
    });
});
