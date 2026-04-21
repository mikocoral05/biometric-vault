import { bufferToBase64url, base64urlToBuffer, randomBytes } from "./utils.js";
import { deriveKeyFromPrf, encryptData, decryptData } from "./crypto.js";

interface VaultConfig {
  credentialId: string;
  duressCredentialId?: string;
  salt: string; // Used for PRF
}

export class BiometricVault {
  private key: CryptoKey;
  private vaultName: string;
  private prefix: string;

  private constructor(vaultName: string, key: CryptoKey) {
    this.vaultName = vaultName;
    this.key = key;
    this.prefix = `biometric_vault_${vaultName}_data_`;
  }

  static async open(vaultName: string): Promise<BiometricVault> {
    const configStr = localStorage.getItem(
      `biometric_vault_config_${vaultName}`,
    );
    if (configStr) {
      // Existing vault, authenticate
      const config: VaultConfig = JSON.parse(configStr);
      const prfSalt = base64urlToBuffer(config.salt);
      const allowCredentials: PublicKeyCredentialDescriptor[] = [
        { id: base64urlToBuffer(config.credentialId), type: "public-key" },
      ];

      if (config.duressCredentialId) {
        allowCredentials.push({
          id: base64urlToBuffer(config.duressCredentialId),
          type: "public-key",
        });
      }

      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          allowCredentials,
          userVerification: "required",
          extensions: {
            prf: {
              eval: {
                first: prfSalt,
              },
            },
          } as any,
        },
      })) as PublicKeyCredential;

      if (!assertion) {
        throw new Error("Authentication failed");
      }

      // Check for duress mode
      if (
        config.duressCredentialId &&
        assertion.id === config.duressCredentialId
      ) {
        BiometricVault.wipeVault(vaultName);
        throw new Error("Duress mode activated: Vault wiped.");
      }

      // Get PRF result
      const clientExtensionResults =
        assertion.getClientExtensionResults() as any;
      const prfResult = clientExtensionResults.prf?.results?.first;

      if (!prfResult) {
        throw new Error(
          "Your authenticator does not support the required PRF extension for hardware-bound encryption.",
        );
      }

      const key = await deriveKeyFromPrf(new Uint8Array(prfResult), prfSalt);
      return new BiometricVault(vaultName, key);
    } else {
      // Create new vault
      const prfSalt = randomBytes(32);
      const userId = randomBytes(16);

      const credential = (await navigator.credentials.create({
        publicKey: {
          challenge: randomBytes(32),
          rp: {
            name: "Biometric Vault",
            id: window.location.hostname,
          },
          user: {
            id: userId,
            name: `${vaultName} User`,
            displayName: `Owner of ${vaultName}`,
          },
          pubKeyCredParams: [
            { type: "public-key", alg: -7 },
            { type: "public-key", alg: -257 },
          ],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            userVerification: "required",
            residentKey: "required",
          },
          extensions: {
            prf: {
              eval: {
                first: prfSalt,
              },
            },
          } as any,
        },
      })) as PublicKeyCredential;

      if (!credential) {
        throw new Error("Registration failed");
      }

      const clientExtensionResults =
        credential.getClientExtensionResults() as any;
      let prfResult = clientExtensionResults.prf?.results?.first;

      // If evaluating during create is not supported or didn't run, we must assert once to get the PRF output
      if (!prfResult) {
        if (!clientExtensionResults.prf?.enabled) {
          throw new Error(
            "Your authenticator does not support the required PRF extension for hardware-bound encryption.",
          );
        }
        // Fallback: get assertion to fetch PRF
        const assertion = (await navigator.credentials.get({
          publicKey: {
            challenge: randomBytes(32),
            allowCredentials: [{ id: credential.rawId, type: "public-key" }],
            userVerification: "required",
            extensions: {
              prf: {
                eval: {
                  first: prfSalt,
                },
              },
            } as any,
          },
        })) as PublicKeyCredential;

        const assertExt = assertion.getClientExtensionResults() as any;
        prfResult = assertExt.prf?.results?.first;
        if (!prfResult)
          throw new Error("Failed to retrieve PRF from authenticator");
      }

      const config: VaultConfig = {
        credentialId: credential.id,
        salt: bufferToBase64url(prfSalt),
      };

      localStorage.setItem(
        `biometric_vault_config_${vaultName}`,
        JSON.stringify(config),
      );

      const key = await deriveKeyFromPrf(new Uint8Array(prfResult), prfSalt);
      return new BiometricVault(vaultName, key);
    }
  }

  // Method to add duress finger
  static async setupDuress(vaultName: string): Promise<void> {
    const configStr = localStorage.getItem(
      `biometric_vault_config_${vaultName}`,
    );
    if (!configStr) throw new Error("Vault does not exist");
    const config: VaultConfig = JSON.parse(configStr);

    const userId = randomBytes(16);
    // Create another credential for duress
    const credential = (await navigator.credentials.create({
      publicKey: {
        challenge: randomBytes(32),
        rp: {
          name: "Biometric Vault (Duress)",
          id: window.location.hostname,
        },
        user: {
          id: userId,
          name: `${vaultName} Duress User`,
          displayName: `Duress for ${vaultName}`,
        },
        pubKeyCredParams: [
          { type: "public-key", alg: -7 },
          { type: "public-key", alg: -257 },
        ],
        authenticatorSelection: {
          authenticatorAttachment: "platform",
          userVerification: "required",
          residentKey: "required",
        },
      },
    })) as PublicKeyCredential;

    if (!credential) throw new Error("Registration failed");

    config.duressCredentialId = credential.id;
    localStorage.setItem(
      `biometric_vault_config_${vaultName}`,
      JSON.stringify(config),
    );
  }

  static wipeVault(vaultName: string): void {
    const prefix = `biometric_vault_${vaultName}_`;
    const keysToRemove: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i);
      if (k?.startsWith(prefix)) {
        keysToRemove.push(k);
      }
    }
    keysToRemove.forEach((k) => localStorage.removeItem(k));
  }

  async set(key: string, value: any): Promise<void> {
    const { iv, ciphertext } = await encryptData(this.key, value);
    localStorage.setItem(
      `${this.prefix}${key}`,
      JSON.stringify({ iv, ciphertext }),
    );
  }

  async get(key: string): Promise<any> {
    const str = localStorage.getItem(`${this.prefix}${key}`);
    if (!str) return null;
    const { iv, ciphertext } = JSON.parse(str);
    try {
      return await decryptData(this.key, iv, ciphertext);
    } catch (e) {
      throw new Error(
        "Failed to decrypt data. Key may be invalid or data corrupted.",
      );
    }
  }

  async remove(key: string): Promise<void> {
    localStorage.removeItem(`${this.prefix}${key}`);
  }

  async getPaperKey(): Promise<string> {
    const rawKey = await crypto.subtle.exportKey("raw", this.key);
    return bufferToBase64url(rawKey);
  }

  static async recover(
    vaultName: string,
    paperKey: string,
  ): Promise<BiometricVault> {
    const rawKey = base64urlToBuffer(paperKey);
    const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", true, [
      "encrypt",
      "decrypt",
    ]);
    return new BiometricVault(vaultName, key);
  }
}
