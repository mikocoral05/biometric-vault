import { describe, it, expect } from "vitest";
import { deriveKeyFromPrf, encryptData, decryptData } from "./crypto.js";

describe("Cryptography Module", () => {
  it("should derive a key, encrypt, and decrypt data correctly", async () => {
    // 1. Generate a mock PRF output (Input Keying Material)
    const mockPrfOutput = new Uint8Array(32);
    crypto.getRandomValues(mockPrfOutput);
    const mockSalt = crypto.getRandomValues(new Uint8Array(32));

    // 2. Derive the AES-GCM key
    const key = await deriveKeyFromPrf(mockPrfOutput, mockSalt);
    expect(key).toBeDefined();
    expect(key.algorithm.name).toBe("AES-GCM");

    // 3. Encrypt some dummy data
    const secretData = { patient: "John Doe", bloodType: "O+" };
    const encrypted = await encryptData(key, secretData);

    expect(encrypted.iv).toBeDefined();
    expect(encrypted.ciphertext).toBeDefined();

    // 4. Decrypt the data and verify it matches the original
    const decrypted = await decryptData(
      key,
      encrypted.iv,
      encrypted.ciphertext,
    );
    expect(decrypted).toEqual(secretData);
  });
});
