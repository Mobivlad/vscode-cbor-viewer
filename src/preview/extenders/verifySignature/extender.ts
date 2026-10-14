/**
 * @fileoverview Extender (preview extender).
 *
 * - Registers the "Verify signature…" button rendered next to COSE signatures.
 * - Asks the user for a key file (and the payload when detached), verifies the signature in the
 *   extension host, and reports the result as a notification and inline in the webview.
 */
import type { PreviewExtender } from '../previewExtender';
import { PreviewSystem } from '../../previewSystem';
import { VERIFY_SIG_TOKEN } from '../../previewHintTokens';
import { decodeVerifyTarget } from '../../../pretty/core/coseVerifyTarget';
import { loadPublicKey, verifyCoseSignature } from './coseVerify';

export const previewExtender: PreviewExtender = {
    id: 'verify-signature',
    register(system): void {
        system.registerPreviewHintKind({
            kind: 'verifySig',
            token: VERIFY_SIG_TOKEN,
            cssClass: 'verify-sig-button',
            displayAsButton: true,
            onClickMessage: { type: 'verifySignature', blobId: '$blobId' },
            contextMenuItems: [
                { label: 'Verify Signature…', message: { type: 'verifySignature', blobId: '$blobId' } }
            ]
        });

        system.registerMessageHandler('verifySignature', async (message, ctx) => {
            const blobId = typeof message.blobId === 'string' ? message.blobId : undefined;
            const raw = blobId ? ctx.blobs.get(blobId) : undefined;
            if (!blobId || !raw) {
                return true;
            }

            const vscode = PreviewSystem.vscode();
            const report = async (status: 'valid' | 'invalid' | 'error', text: string, keyPath?: string): Promise<void> => {
                if (status === 'valid') {
                    void vscode.window.showInformationMessage(`CBOR Viewer: ${text}`);
                } else {
                    void vscode.window.showErrorMessage(`CBOR Viewer: ${text}`);
                }
                try {
                    await ctx.postMessage?.({ type: 'verifySignatureResult', blobId, status, text, keyPath });
                } catch {
                    // The webview may have been closed meanwhile.
                }
            };

            const target = decodeVerifyTarget(raw);
            if (!target) {
                await report('error', 'Unable to read signature data for verification.');
                return true;
            }

            const keyUris = await vscode.window.showOpenDialog({
                canSelectMany: false,
                title: 'Select a public key or certificate to verify the signature',
                openLabel: 'Verify with this key',
                filters: {
                    'Keys and certificates': ['pem', 'crt', 'cer', 'der', 'pub', 'key', 'jwk', 'json', 'cbor', 'cose'],
                    'All Files': ['*']
                }
            });
            const keyUri = keyUris?.[0];
            if (!keyUri) {
                return true;
            }

            let payload: Buffer | undefined;
            if (target.payloadBlobId !== undefined) {
                payload = ctx.blobs.get(target.payloadBlobId);
            } else {
                const payloadUris = await vscode.window.showOpenDialog({
                    canSelectMany: false,
                    title: 'The payload is detached: select the payload file',
                    openLabel: 'Use as payload'
                });
                if (!payloadUris?.[0]) {
                    return true;
                }
                payload = Buffer.from(await vscode.workspace.fs.readFile(payloadUris[0]));
            }
            if (!payload) {
                await report('error', 'Signed payload is not available.');
                return true;
            }

            const keyName = keyUri.path.split('/').pop() || keyUri.path;
            try {
                const key = loadPublicKey(Buffer.from(await vscode.workspace.fs.readFile(keyUri)));
                const result = verifyCoseSignature(target, payload, key);
                await report(
                    result.valid ? 'valid' : 'invalid',
                    `Signature is ${result.valid ? 'VALID' : 'INVALID'} (${result.algorithm}, key: ${keyName}).`,
                    keyUri.fsPath
                );
            } catch (e) {
                const msg = e instanceof Error ? e.message : String(e);
                await report('error', `Signature verification failed (key: ${keyName}): ${msg}`, keyUri.fsPath);
            }
            return true;
        });
    }
};
