import { bufferToBase64url, base64urlToBuffer } from './utils.js';

export async function deriveKeyFromPrf(
  ikm: Uint8Array,
  salt: Uint8Array,
): Promise<CryptoKey> {
  const importedKey = await crypto.subtle.importKey(
    'raw',
    ikm as unknown as BufferSource,
    'HKDF',
    false,
    ['deriveKey'],
  );
  return await crypto.subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: salt as unknown as BufferSource,
      info: new TextEncoder().encode(
        'biometric-vault-encryption',
      ) as unknown as BufferSource,
    },
    importedKey,
    { name: 'AES-GCM', length: 256 },
    true, // Extractable so we can generate a Paper Key
    ['encrypt', 'decrypt'],
  );
}

export async function encryptData(
  key: CryptoKey,
  data: any,
): Promise<{ iv: string; ciphertext: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedData = new TextEncoder().encode(JSON.stringify(data));
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    key,
    encodedData as unknown as BufferSource,
  );
  return {
    iv: bufferToBase64url(iv),
    ciphertext: bufferToBase64url(encrypted),
  };
}

export async function decryptData(
  key: CryptoKey,
  iv: string,
  ciphertext: string,
): Promise<any> {
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64urlToBuffer(iv) as unknown as BufferSource },
    key,
    base64urlToBuffer(ciphertext) as unknown as BufferSource,
  );
  return JSON.parse(new TextDecoder().decode(decrypted));
}
