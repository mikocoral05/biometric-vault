# biometric-vault

The Passkey-Secured Storage Library.

Currently, if a developer wants to encrypt data in localStorage, they usually hardcode a "secret key" in their JavaScript. This is useless because any hacker (or malicious Chrome extension) can just read the source code and find the key.

**biometric-vault** uses the browser's native WebAuthn API (the same tech behind Passkeys/FaceID) to encrypt and decrypt data. The encryption key is derived using the WebAuthn PRF extension and bound to the user's Hardware Security Module (TPM). It is only released when the user physically touches their fingerprint scanner or looks at their FaceID.

## 🚀 Features

- **Hardware-Bound Keys**: Uses the WebAuthn `prf` extension to bind encryption keys to the physical device. If someone steals the database/localStorage, they can't open it without the user's physical presence.
- **Duress Mode**: You can set a "secondary fingerprint" (like your pinky finger) that, when scanned, wipes the local storage instead of opening it (for high-security situations).
- **Auto-Entropy Injection**: The library uses the `crypto.getRandomValues()` API to inject real-world randomness into key generation and encryption IVs.
- **Zero-Knowledge Recovery**: Generate a "Paper Key" that can be stored offline in case the device's biometric sensor breaks.

## Installation

```bash
npm install biometric-vault
```

## Usage

```typescript
import { BiometricVault } from 'biometric-vault';

// This will trigger a FaceID/Fingerprint popup automatically
const vault = await BiometricVault.open('medical_records');

await vault.set('test_results', { cholesterol: 'low' });

// If someone else tries to read this, it returns encrypted garbage 
// unless the owner provides their biometric again.
const results = await vault.get('test_results');
console.log(results); // { cholesterol: 'low' }
```

### Duress Mode
Register a secondary fingerprint to wipe the vault when scanned.
```typescript
await BiometricVault.setupDuress('medical_records');
// Scans the duress finger. Next time `open()` is called with this finger, the vault is wiped.
```

### Paper Key Recovery
If the user loses their hardware authenticator, they can recover using a Paper Key.
```typescript
const paperKey = await vault.getPaperKey();
// Store paperKey safely offline

// ...Later, to recover:
const recoveredVault = await BiometricVault.recover('medical_records', paperKey);
await recoveredVault.get('test_results');
```
