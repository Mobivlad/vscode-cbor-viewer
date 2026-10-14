/**
 * @fileoverview Extender (preview extender).
 *
 * - Registers webview actions and/or commands related to preview links.
 * - Validates webview messages before performing privileged extension-host work.
 * - Handles the "Save bin" action: writes a referenced byte blob to a user-chosen file.
 */
import type { PreviewExtender } from '../previewExtender';
import { PreviewSystem } from '../../previewSystem';

export const previewExtender: PreviewExtender = {
    id: 'save-blob',
    register(system): void {
        system.registerMessageHandler('saveBlob', async (message, ctx) => {
            const blobId = typeof message.blobId === 'string' ? message.blobId : undefined;
            if (!blobId) {
                return true;
            }

            const bytes = ctx.blobs.get(blobId);
            if (!bytes) {
                return true;
            }

            const vscode = PreviewSystem.vscode();
            const target = await vscode.window.showSaveDialog({
                saveLabel: 'Save bytes',
                defaultUri: vscode.Uri.file(`${blobId}.bin`),
                filters: { 'Binary': ['bin'], 'All Files': ['*'] }
            });
            if (!target) {
                return true;
            }

            await vscode.workspace.fs.writeFile(target, new Uint8Array(bytes));
            return true;
        });
    }
};
