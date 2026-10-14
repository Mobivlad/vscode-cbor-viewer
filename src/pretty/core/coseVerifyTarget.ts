/**
 * @fileoverview COSE signature verification target (pretty core).
 *
 * Signature formatters register a compact CBOR-encoded descriptor holding everything needed to
 * rebuild the Sig_structure (RFC 9052 §4.4). The verify-signature preview extender decodes it
 * on demand in the extension host, so no key material or crypto runs during formatting.
 */
import * as cbor from 'cbor';
import { toBuffer } from '../util';
import { toInt32 } from './numeric';

export interface CoseVerifyTarget {
    context: 'Signature1' | 'Signature';
    bodyProtected: Buffer;
    /** Signer protected headers (COSE_Sign only). */
    signProtected?: Buffer;
    /** Blob id of the embedded payload; undefined when the payload is detached. */
    payloadBlobId?: string;
    signature: Buffer;
    alg?: number;
}

export function encodeVerifyTarget(target: CoseVerifyTarget): Buffer {
    const encoded = cbor.encodeOne([
        target.context,
        target.bodyProtected,
        target.signProtected ?? null,
        target.payloadBlobId ?? null,
        target.signature,
        target.alg ?? null
    ]);
    return Buffer.isBuffer(encoded) ? encoded : Buffer.from(encoded);
}

export function decodeVerifyTarget(bytes: Buffer): CoseVerifyTarget | undefined {
    let arr: unknown;
    try {
        arr = cbor.decodeFirstSync(bytes);
    } catch {
        return undefined;
    }
    if (!Array.isArray(arr) || arr.length !== 6) {
        return undefined;
    }
    const [context, bodyProtected, signProtected, payloadBlobId, signature, alg] = arr;
    const bodyBuf = toBuffer(bodyProtected);
    const sigBuf = toBuffer(signature);
    if ((context !== 'Signature1' && context !== 'Signature') || !bodyBuf || !sigBuf) {
        return undefined;
    }
    const target: CoseVerifyTarget = { context, bodyProtected: bodyBuf, signature: sigBuf };
    const signBuf = toBuffer(signProtected);
    if (signBuf) {
        target.signProtected = signBuf;
    }
    if (typeof payloadBlobId === 'string') {
        target.payloadBlobId = payloadBlobId;
    }
    const algId = toInt32(alg);
    if (algId !== null) {
        target.alg = algId;
    }
    return target;
}

/** Read the `alg` header (label 1), preferring the protected bucket. */
export function getCoseAlgorithmId(protectedMap: Map<unknown, unknown>, unprotectedMap: Map<unknown, unknown> | null): number | undefined {
    const raw = protectedMap.has(1) ? protectedMap.get(1) : unprotectedMap?.get(1);
    return toInt32(raw) ?? undefined;
}
