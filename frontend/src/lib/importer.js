// Shared tunnel import paths for App (picker + native drop) and Onboarding.
// Go sanitizes names and picks a unique one; every function here resolves to
// a list of { name, error? } results and never throws.
import { TunnelService } from '../../bindings/github.com/steiale/wireguide/internal/app';
import { uint8ArrayToBase64 } from './encoding.js';
import { errText } from './errors.js';

export const isZip = (n) => /\.zip$/i.test(n);
export const isConfig = (n) => /\.(conf|ovpn)$/i.test(n);
export const isImage = (n) => /\.(png|jpe?g|gif)$/i.test(n);
export const isImportable = (n) => isZip(n) || isConfig(n) || isImage(n);

// Wails serialises []byte as base64; see encoding.js for the chunked encoder.
async function toBase64(file) {
  return uint8ArrayToBase64(new Uint8Array(await file.arrayBuffer()));
}

// importFile imports a browser File (file picker): .conf, .ovpn, .zip or a
// QR code image.
export async function importFile(file) {
  try {
    if (isZip(file.name)) return (await TunnelService.ImportZipData(await toBase64(file))) ?? [];
    if (isImage(file.name) || file.type?.startsWith('image/')) return [{ name: await TunnelService.ImportQRFromBytes(await toBase64(file), file.name) }];
    const info = await TunnelService.ImportFile(file.name, await file.text());
    return [{ name: info.name }];
  } catch (e) {
    return [{ name: file.name, error: errText(e) }];
  }
}

// importPath imports a file the Go side granted (native drop).
export async function importPath(path) {
  try {
    if (isZip(path)) return (await TunnelService.ImportZip(path)) ?? [];
    if (isImage(path)) return [{ name: await TunnelService.ImportQRFromPath(path) }];
    const content = await TunnelService.ReadFile(path);
    const info = await TunnelService.ImportFile(path, content);
    return [{ name: info.name }];
  } catch (e) {
    return [{ name: path.split('/').pop() || path, error: errText(e) }];
  }
}

// pickFile opens the native file picker. The input is attached to the DOM
// until onchange fires: WKWebView can GC a detached input mid-selection.
export function pickFile(accept, onFile) {
  const input = document.createElement('input');
  input.type = 'file';
  input.accept = accept;
  input.style.display = 'none';
  document.body.appendChild(input);
  input.onchange = (e) => {
    document.body.removeChild(input);
    const file = e.target.files?.[0];
    if (file) onFile(file);
  };
  input.click();
}
