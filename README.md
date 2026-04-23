# tunnls-e2e

End-to-end encryption primitives for [Tunnls](https://tunnls.com) sessions. Runs entirely in the browser via WebCrypto. No external dependencies.

This module is published separately from the main tunnls server so that anyone can audit exactly what the browser is asked to run.

## What this does

A tunnls session is a real-time link between an **operator** and a **visitor**. Field values the visitor types (name, phone, etc.) travel through the tunnls server before reaching the operator's browser. Without E2E, the server sees plaintext. With this module, the server sees only ciphertext.

## Design

- **Key agreement:** ECDH on P-256
- **Key derivation:** HKDF-SHA256, 32-byte session key
- **Symmetric cipher:** AES-256-GCM, 96-bit random nonces
- **AAD:** `"{roomCode}:{fieldId}:{kind}:{from}:{v}:{seq}"` binds ciphertext to its session, field, kind (`value` or `label`), sending party (`operator` or `visitor`), protocol version, and monotonic sequence — so an envelope replayed across fields, reclassified as a different kind, or spoofed as if from the other party fails to decrypt
- **MITM detection:** both parties derive a deterministic 25-ball bingo-style grid from the session key. Visitor picks N balls freely, operator resolves the positions through its own grid, and the parties compare ball names over a trusted out-of-band channel (phone). If a MITM is tampering with key exchange, the grids diverge and the ball names don't match.

## API

All functions are `async` (WebCrypto is promise-based).

```js
import * as e2e from "./src/e2e.js";

// Key exchange
const keypair = await e2e.generateKeypair();
const pubJwk  = await e2e.exportPublicKey(keypair.publicKey);
const peerKey = await e2e.importPublicKey(peerJwk);
const sessKey = await e2e.deriveSessionKey(keypair.privateKey, peerKey, roomCode);

// Verification grid (25 balls, 5 unique per column B/I/N/G/O, each in 1..99)
const grid = await e2e.deriveGrid(sessKey);
// e.g. { B: [1,2,3,4,5], I: [16,17,18,19,20], N: [31,32,33,34,35],
//        G: [46,47,48,49,50], O: [61,62,63,64,65] }

// Resolve a flat position (0..24, row-major: row = floor(i/5), col = i%5)
// to a ball name. Columns are ordered B, I, N, G, O.
e2e.resolveBall(grid, 0);  // => "B1"   (row 0, col 0)
e2e.resolveBall(grid, 7);  // => "N32"  (row 1, col 2)
e2e.resolveBall(grid, 24); // => "O65"  (row 4, col 4)

// Envelope encryption — handles both field values and labels, in either direction.
const envelope = await e2e.encryptEnvelope(sessKey, "Alice", {
  roomCode,
  fieldId,
  kind: e2e.KIND_VALUE,        // or e2e.KIND_LABEL
  from: e2e.PARTY_VISITOR,     // or e2e.PARTY_OPERATOR
  v: e2e.PROTOCOL_VERSION,
  seq,
});
// envelope = { v, seq, kind, from, fieldId, nonce, ct, tag }
// (nonce/ct/tag are base64; the others are integrity-bound via AAD)

const plaintext = await e2e.decryptEnvelope(sessKey, envelope, { roomCode });
```

## Running tests

Requires Node 19+ (for `globalThis.crypto.subtle`).

```
node --test assets/vendor/tunnls-e2e/test/
```

## Limitations

- **Not a defense against targeted JS tampering.** This module is served by the tunnls server. A malicious server could serve different JS to different users. Defending against that requires Subresource Integrity + browser-side verification we don't have yet.
- **No forward secrecy across sessions.** Each session generates a fresh keypair in memory and discards it when the session ends. There's no long-term identity to compromise, but there's also no cross-session FS beyond that.
- **Coarse field type is not encrypted.** Each field has a `text | phone | email | date` category that the visitor's device uses to pick the right input keyboard / formatting. This category travels plaintext alongside the encrypted label and value envelopes. Setting everything to `text` drops this category entirely if you don't want the server to see it.

## License

MIT. See [LICENSE](./LICENSE).
