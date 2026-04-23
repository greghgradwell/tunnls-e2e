export const PROTOCOL_VERSION = 2;

export const KIND_VALUE = "value";
export const KIND_LABEL = "label";
export const PARTY_OPERATOR = "operator";
export const PARTY_VISITOR = "visitor";

const COLUMNS = ["B", "I", "N", "G", "O"];
const BALLS_PER_COLUMN = 5;
const COLUMN_RANGE_MAX = 99;
const SESSION_INFO = new TextEncoder().encode("tunnls-session-v1");
const GRID_INFO_PREFIX = "grid-v1-column-";

export async function generateKeypair() {
  return crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
}

export async function exportPublicKey(publicKey) {
  return crypto.subtle.exportKey("jwk", publicKey);
}

export async function importPublicKey(jwk) {
  return crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    [],
  );
}

export async function deriveSessionKey(privateKey, peerPublicKey, roomCode) {
  const sharedBits = await crypto.subtle.deriveBits(
    { name: "ECDH", public: peerPublicKey },
    privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedBits,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const sessionBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new TextEncoder().encode(roomCode),
      info: SESSION_INFO,
    },
    hkdfKey,
    256,
  );
  return new Uint8Array(sessionBits);
}

export async function deriveGrid(sessionKey) {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sessionKey,
    "HKDF",
    false,
    ["deriveBits"],
  );

  const grid = {};
  for (const letter of COLUMNS) {
    const info = new TextEncoder().encode(GRID_INFO_PREFIX + letter);
    // BALLS_PER_COLUMN shuffle steps × 4 bytes of randomness each
    const bits = await crypto.subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(), info },
      hkdfKey,
      BALLS_PER_COLUMN * 4 * 8,
    );
    const rand = new DataView(bits);

    const pool = Array.from({ length: COLUMN_RANGE_MAX }, (_, i) => i + 1);
    // Partial Fisher-Yates: stop after BALLS_PER_COLUMN picks. Each step swaps
    // pool[i] with a random earlier position, so the last BALLS_PER_COLUMN
    // elements end up as a uniform sample. Modulo bias is <2^-24 per step,
    // negligible for human-verified MITM detection.
    for (
      let i = pool.length - 1, step = 0;
      step < BALLS_PER_COLUMN;
      i--, step++
    ) {
      const j = rand.getUint32(step * 4, false) % (i + 1);
      [pool[i], pool[j]] = [pool[j], pool[i]];
    }
    grid[letter] = pool.slice(pool.length - BALLS_PER_COLUMN);
  }
  return grid;
}

export function resolveBall(grid, position) {
  if (!Number.isInteger(position) || position < 0 || position > 24) {
    throw new Error(`position out of range: ${position}`);
  }
  const row = Math.floor(position / 5);
  const col = position % 5;
  const letter = COLUMNS[col];
  return `${letter}${grid[letter][row]}`;
}

export async function encryptEnvelope(
  sessionKey,
  plaintext,
  { roomCode, fieldId, kind, from, v, seq },
) {
  const aesKey = await crypto.subtle.importKey(
    "raw",
    sessionKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"],
  );
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  // AAD binds ciphertext to session / field / kind (value|label) / sending
  // party / protocol version / seq. Namespacing by kind+from prevents a
  // label envelope from being replayed as a value, and prevents one party's
  // envelope being accepted as if it came from the other.
  // Callers must ensure roomCode/fieldId/kind/from do not contain ":".
  const aad = new TextEncoder().encode(
    `${roomCode}:${fieldId}:${kind}:${from}:${v}:${seq}`,
  );
  const pt = new TextEncoder().encode(plaintext);

  const ctWithTag = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      aesKey,
      pt,
    ),
  );
  const ct = ctWithTag.slice(0, ctWithTag.length - 16);
  const tag = ctWithTag.slice(ctWithTag.length - 16);

  return {
    v,
    seq,
    kind,
    from,
    fieldId,
    nonce: toBase64(nonce),
    ct: toBase64(ct),
    tag: toBase64(tag),
  };
}

export async function decryptEnvelope(sessionKey, envelope, { roomCode }) {
  const { v, seq, kind, from, fieldId, nonce, ct, tag } = envelope;
  const aesKey = await crypto.subtle.importKey(
    "raw",
    sessionKey,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const nonceBytes = fromBase64(nonce);
  const ctBytes = fromBase64(ct);
  const tagBytes = fromBase64(tag);

  const ctWithTag = new Uint8Array(ctBytes.length + tagBytes.length);
  ctWithTag.set(ctBytes, 0);
  ctWithTag.set(tagBytes, ctBytes.length);

  const aad = new TextEncoder().encode(
    `${roomCode}:${fieldId}:${kind}:${from}:${v}:${seq}`,
  );
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonceBytes, additionalData: aad, tagLength: 128 },
    aesKey,
    ctWithTag,
  );
  return new TextDecoder().decode(pt);
}

function toBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function fromBase64(str) {
  return Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
}
