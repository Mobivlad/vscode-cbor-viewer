/**
 * @fileoverview Cose Sign1 Formatter (pretty extender).
 *
 * - Contributes pretty-formatting behavior for a specific domain (COSE/CWT/SCITT/etc.).
 * - Registers formatters, labels, and preview generators with the core pipeline.
 * - Ordering matters: prefer specific formatters over generic ones.
 */
import type { PrettyFormatter, PrettyFormatterContext } from '../../registry';
import type { CoseInspectionResult } from './coseSign1InspectionTypes';
import { asCborMap, toBuffer } from '../../util';
import { isLikelyCoseSign1, unwrapCoseSign1Tag } from './coseSign1Match';
import {
    buildCoseHeadersMap,
    buildPayloadInfo,
    buildSignatureInfo,
    cleanEmptyHeaders,
    decodeProtectedHeaders,
    delegateAndMergeHeaders,
    estimateTotalSizeBytes,
    getContentTypeString,
} from '../../core/coseMessageCommon';
import { getCoseAlgorithmId } from '../../core/coseVerifyTarget';

/**
 * COSE_Sign1 inspection formatter.
 *
 * Extender philosophy:
 * - This formatter focuses on COSE_Sign1 structure recognition and producing the
 *   top-level inspection model.
 * - Domain projections (like CWT claims) are delegated via `ctx.format(...)`.
 * - Label mapping is delegated via `ctx.labels` (extender-registered).
 */
export const CoseSign1Formatter: PrettyFormatter = {
    id: 'cose-sign1',
    order: 100,
    canFormat(value: unknown, ctx: PrettyFormatterContext): boolean {
        void ctx;
        const candidate = unwrapCoseSign1Tag(value);
        return isLikelyCoseSign1(candidate);
    },
    format(value: unknown, ctx: PrettyFormatterContext): unknown {
        const candidate = unwrapCoseSign1Tag(value);
        if (!isLikelyCoseSign1(candidate)) {
            return value;
        }

        const totalSizeBytes = estimateTotalSizeBytes(value, ctx);
        return inspectCoseSign1(ctx, candidate, totalSizeBytes);
    }
};

/**
 * COSE_Sign1 = [ protected: bstr, unprotected: map, payload: bstr/nil, signature: bstr ]
 */
function inspectCoseSign1(ctx: PrettyFormatterContext, data: unknown[], totalSizeBytes: number): CoseInspectionResult {
    const protectedBytes = toBuffer(data[0]);
    const unprotected = data[1];
    const payload = data[2];

    const protectedMap = decodeProtectedHeaders(protectedBytes);
    const unprotectedMap = asCborMap(unprotected);

    const protectedHeaders = buildCoseHeadersMap(ctx, protectedMap);
    const contentType = getContentTypeString(protectedMap);
    const unprotectedHeaders = buildCoseHeadersMap(ctx, unprotectedMap);

    delegateAndMergeHeaders(ctx, protectedMap, unprotectedMap, protectedHeaders, unprotectedHeaders);

    const payloadBytes = toBuffer(payload);
    const signatureBytes = toBuffer(data[3]);
    const result: CoseInspectionResult = {
        protectedHeaders,
        unprotectedHeaders,
        payload: buildPayloadInfo(ctx, payload, contentType),
        signature: buildSignatureInfo(ctx, data[3], totalSizeBytes, signatureBytes ? {
            context: 'Signature1',
            bodyProtected: protectedBytes ?? Buffer.alloc(0),
            payloadBlobId: payloadBytes ? ctx.registerBlob(payloadBytes) : undefined,
            signature: signatureBytes,
            alg: getCoseAlgorithmId(protectedMap, unprotectedMap)
        } : undefined)
    };

    cleanEmptyHeaders(result);
    return result;
}

