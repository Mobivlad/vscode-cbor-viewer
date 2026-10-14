/**
 * @fileoverview COSE signature verification (preview extender helper).
 *
 * Pure Node crypto logic, independent of VS Code APIs:
 * - rebuilds the Sig_structure (RFC 9052 §4.4)
 * - loads a public key from PEM/DER (SPKI or X.509), JWK, or COSE_Key
 * - verifies ECDSA, EdDSA, RSASSA-PSS and RSASSA-PKCS1-v1_5 signatures
 */
import * as cbor from 'cbor';
import { constants, createPublicKey, verify, X509Certificate, type KeyObject } from 'crypto';
import type { CoseVerifyTarget } from '../../../pretty/core/coseVerifyTarget';

type AlgKind = 'ecdsa' | 'eddsa' | 'pss' | 'pkcs1';

interface AlgInfo {
    name: string;
    kind: AlgKind;
    hash?: 'sha256' | 'sha384' | 'sha512';
}

const ALGORITHMS: Record<number, AlgInfo> = {
    [-7]: { name: 'ES256', kind: 'ecdsa', hash: 'sha256' },
    [-35]: { name: 'ES384', kind: 'ecdsa', hash: 'sha384' },
    [-36]: { name: 'ES512', kind: 'ecdsa', hash: 'sha512' },
    [-9]: { name: 'ESP256', kind: 'ecdsa', hash: 'sha256' },
    [-51]: { name: 'ESP384', kind: 'ecdsa', hash: 'sha384' },
    [-52]: { name: 'ESP512', kind: 'ecdsa', hash: 'sha512' },
    [-8]: { name: 'EdDSA', kind: 'eddsa' },
    [-19]: { name: 'Ed25519', kind: 'eddsa' },
    [-53]: { name: 'Ed448', kind: 'eddsa' },
    [-37]: { name: 'PS256', kind: 'pss', hash: 'sha256' },
    [-38]: { name: 'PS384', kind: 'pss', hash: 'sha384' },
    [-39]: { name: 'PS512', kind: 'pss', hash: 'sha512' },
    [-257]: { name: 'RS256', kind: 'pkcs1', hash: 'sha256' },
    [-258]: { name: 'RS384', kind: 'pkcs1', hash: 'sha384' },
    [-259]: { name: 'RS512', kind: 'pkcs1', hash: 'sha512' }
};

const HASH_LENGTH = { sha256: 32, sha384: 48, sha512: 64 } as const;

const KEY_TYPES_BY_KIND: Record<AlgKind, string[]> = {
    ecdsa: ['ec'],
    eddsa: ['ed25519', 'ed448'],
    pss: ['rsa', 'rsa-pss'],
    pkcs1: ['rsa']
};

export interface CoseVerifyResult {
    valid: boolean;
    algorithm: string;
}

export function buildSigStructure(target: CoseVerifyTarget, payload: Buffer, externalAad: Buffer = Buffer.alloc(0)): Buffer {
    const structure = target.context === 'Signature1'
        ? ['Signature1', target.bodyProtected, externalAad, payload]
        : ['Signature', target.bodyProtected, target.signProtected ?? Buffer.alloc(0), externalAad, payload];
    const encoded = cbor.encodeOne(structure);
    return Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
}

export function verifyCoseSignature(target: CoseVerifyTarget, payload: Buffer, key: KeyObject): CoseVerifyResult {
    if (target.alg === undefined) {
        throw new Error('The signature has no "alg" (label 1) header.');
    }
    const alg = ALGORITHMS[target.alg];
    if (!alg) {
        throw new Error(`Unsupported COSE algorithm ${target.alg}.`);
    }
    const keyType = key.asymmetricKeyType ?? 'unknown';
    if (!KEY_TYPES_BY_KIND[alg.kind].includes(keyType)) {
        throw new Error(`Key type "${keyType}" cannot verify ${alg.name} signatures.`);
    }

    const tbs = buildSigStructure(target, payload);
    let valid: boolean;
    switch (alg.kind) {
        case 'ecdsa':
            valid = verify(alg.hash!, tbs, { key, dsaEncoding: 'ieee-p1363' }, target.signature);
            break;
        case 'eddsa':
            valid = verify(null, tbs, key, target.signature);
            break;
        case 'pss':
            valid = verify(alg.hash!, tbs, {
                key,
                padding: constants.RSA_PKCS1_PSS_PADDING,
                saltLength: HASH_LENGTH[alg.hash!]
            }, target.signature);
            break;
        case 'pkcs1':
            valid = verify(alg.hash!, tbs, { key, padding: constants.RSA_PKCS1_PADDING }, target.signature);
            break;
    }
    return { valid, algorithm: alg.name };
}

/**
 * Load a public key from file bytes. Accepts PEM (public key, private key, or certificate),
 * DER (SPKI or X.509 certificate), JWK JSON, or a CBOR-encoded COSE_Key.
 */
export function loadPublicKey(bytes: Buffer): KeyObject {
    const text = bytes.toString('utf8').trim();

    if (text.startsWith('-----BEGIN')) {
        if (/-----BEGIN CERTIFICATE-----/.test(text)) {
            return new X509Certificate(text).publicKey;
        }
        return createPublicKey(text);
    }

    if (text.startsWith('{')) {
        let jwk: Record<string, unknown>;
        try {
            jwk = JSON.parse(text);
        } catch {
            throw new Error('Key file looks like JSON but could not be parsed.');
        }
        return createPublicKey({ key: toPublicJwk(jwk), format: 'jwk' });
    }

    const coseKey = tryDecodeCoseKey(bytes);
    if (coseKey) {
        return createPublicKey({ key: coseKeyToJwk(coseKey), format: 'jwk' });
    }

    try {
        return new X509Certificate(bytes).publicKey;
    } catch {
        // not a DER certificate; try SPKI below
    }
    try {
        return createPublicKey({ key: bytes, format: 'der', type: 'spki' });
    } catch {
        throw new Error('Unrecognized key format. Use PEM/DER (public key or certificate), JWK, or COSE_Key.');
    }
}

function toPublicJwk(jwk: Record<string, unknown>): any {
    const { d, p, q, dp, dq, qi, ...pub } = jwk;
    void d; void p; void q; void dp; void dq; void qi;
    return pub;
}

function tryDecodeCoseKey(bytes: Buffer): Map<unknown, unknown> | undefined {
    try {
        const decoded = cbor.decodeFirstSync(bytes);
        return decoded instanceof Map && decoded.has(1) ? decoded : undefined;
    } catch {
        return undefined;
    }
}

const COSE_CURVES: Record<number, string> = { 1: 'P-256', 2: 'P-384', 3: 'P-521', 6: 'Ed25519', 7: 'Ed448' };

function coseKeyToJwk(key: Map<unknown, unknown>): any {
    const b64 = (label: number): string => {
        const v = key.get(label);
        if (!Buffer.isBuffer(v) && !(v instanceof Uint8Array)) {
            throw new Error(`COSE_Key parameter ${label} is missing or not a byte string.`);
        }
        return Buffer.from(v).toString('base64url');
    };
    const crv = (): string => {
        const name = COSE_CURVES[Number(key.get(-1))];
        if (!name) {
            throw new Error(`Unsupported COSE_Key curve ${String(key.get(-1))}.`);
        }
        return name;
    };

    switch (key.get(1)) {
        case 1:
            return { kty: 'OKP', crv: crv(), x: b64(-2) };
        case 2:
            return { kty: 'EC', crv: crv(), x: b64(-2), y: b64(-3) };
        case 3:
            return { kty: 'RSA', n: b64(-1), e: b64(-2) };
        default:
            throw new Error(`Unsupported COSE_Key kty ${String(key.get(1))}.`);
    }
}
