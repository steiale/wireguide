// Shared encoding helpers.
//
// Wails serialises Go []byte as a base64 JSON string, so JS callers must
// encode bytes manually before passing them to a *Data RPC method. The
// naïve `btoa(String.fromCharCode(...bytes))` blows the JS call stack
// when the byte array is larger than ~120 KB (the spread operator pushes
// every byte as a separate arg). We chunk through subarray() instead so
// the per-call argument count stays bounded regardless of input size.

const CHUNK = 8192;

export function uint8ArrayToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}
