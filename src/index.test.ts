import { describe, it, expect, vi, beforeEach } from "vitest";
import { BiometricVault } from "./index.js";

// 1. Mock LocalStorage
const localStorageMock = (() => {
  let store: Record<string, string> = {};
  return {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value.toString();
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    get length() {
      return Object.keys(store).length;
    },
    key: vi.fn((i: number) => Object.keys(store)[i] || null),
  };
})();
vi.stubGlobal("localStorage", localStorageMock);
vi.stubGlobal("window", { location: { hostname: "localhost" } });

// 2. Mock WebAuthn API
const mockPrfResult = new ArrayBuffer(32); // Simulating the 32-byte hardware key output
const mockCredential = {
  id: "bW9jay1pZA", // Valid base64url representation
  rawId: new ArrayBuffer(16),
  getClientExtensionResults: () => ({
    prf: { results: { first: mockPrfResult } },
  }),
};

const mockNavigator = {
  credentials: {
    create: vi.fn(),
    get: vi.fn(),
  },
};
vi.stubGlobal("navigator", mockNavigator);

describe("BiometricVault Main Class", () => {
  beforeEach(() => {
    // Reset everything before each test
    localStorageMock.clear();
    vi.clearAllMocks();

    // Default the mock to simulate a successful FaceID/Fingerprint scan
    mockNavigator.credentials.create.mockResolvedValue(mockCredential);
    mockNavigator.credentials.get.mockResolvedValue(mockCredential);
  });

  it("should create a new vault and save to localStorage", async () => {
    const vault = await BiometricVault.open("my_vault");

    expect(mockNavigator.credentials.create).toHaveBeenCalled();
    expect(localStorageMock.setItem).toHaveBeenCalledWith(
      "biometric_vault_config_my_vault",
      expect.any(String),
    );
    expect(vault).toBeDefined();
  });

  it("should encrypt set() data and decrypt get() data", async () => {
    const vault = await BiometricVault.open("my_vault");
    const secretData = { patient: "Alice", diagnosis: "Healthy" };

    await vault.set("record_1", secretData);

    // Verify it was actually encrypted before hitting localStorage
    const savedRaw = localStorageMock.getItem(
      "biometric_vault_my_vault_data_record_1",
    );
    expect(savedRaw).toContain("ciphertext");
    expect(savedRaw).not.toContain("Alice");

    // Verify it can be decrypted back to the original object
    const decrypted = await vault.get("record_1");
    expect(decrypted).toEqual(secretData);
  });

  it("should wipe the vault if duress mode is triggered", async () => {
    const vault = await BiometricVault.open("spy_vault");
    await vault.set("intel", "Launch codes");

    // Mock creating a secondary duress credential
    mockNavigator.credentials.create.mockResolvedValueOnce({
      id: "ZHVyZXNzLWlk",
    }); // Valid base64url representation
    await BiometricVault.setupDuress("spy_vault");

    // Simulate user authenticating with the duress finger instead of the main one
    mockNavigator.credentials.get.mockResolvedValueOnce({ id: "ZHVyZXNzLWlk" });

    // Opening it should throw the self-destruct error
    await expect(BiometricVault.open("spy_vault")).rejects.toThrow(
      "Duress mode activated: Vault wiped.",
    );

    // Verify the data was completely erased from localStorage
    expect(
      localStorageMock.getItem("biometric_vault_spy_vault_data_intel"),
    ).toBeNull();
  });

  it("should generate a paper key and recover the vault offline", async () => {
    const vault = await BiometricVault.open("recovery_vault");
    await vault.set("secret", "My hidden treasure");

    // Generate the offline paper key
    const paperKey = await vault.getPaperKey();
    expect(typeof paperKey).toBe("string");
    expect(paperKey.length).toBeGreaterThan(0);

    // Simulate losing the device and recovering using ONLY the paper key
    const recoveredVault = await BiometricVault.recover(
      "recovery_vault",
      paperKey,
    );

    // The recovered vault should be able to decrypt the data without WebAuthn
    const decrypted = await recoveredVault.get("secret");
    expect(decrypted).toEqual("My hidden treasure");
  });
});
