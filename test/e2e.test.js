import { test } from "node:test";
import assert from "node:assert/strict";
import * as e2e from "../src/e2e.js";

const ROOM_CODE = "123456789";

async function deriveBothSides(roomCode = ROOM_CODE) {
  const alice = await e2e.generateKeypair();
  const bob = await e2e.generateKeypair();

  const aliceSees = await e2e.importPublicKey(
    await e2e.exportPublicKey(bob.publicKey),
  );
  const bobSees = await e2e.importPublicKey(
    await e2e.exportPublicKey(alice.publicKey),
  );

  const aliceKey = await e2e.deriveSessionKey(
    alice.privateKey,
    aliceSees,
    roomCode,
  );
  const bobKey = await e2e.deriveSessionKey(bob.privateKey, bobSees, roomCode);

  return { aliceKey, bobKey };
}

test("generateKeypair produces an ECDH P-256 keypair", async () => {
  const { publicKey, privateKey } = await e2e.generateKeypair();
  assert.equal(publicKey.algorithm.name, "ECDH");
  assert.equal(publicKey.algorithm.namedCurve, "P-256");
  assert.equal(privateKey.algorithm.name, "ECDH");
});

test("public key exports to JWK and reimports", async () => {
  const { publicKey } = await e2e.generateKeypair();
  const jwk = await e2e.exportPublicKey(publicKey);
  assert.equal(jwk.kty, "EC");
  assert.equal(jwk.crv, "P-256");
  assert.ok(jwk.x && jwk.y);

  const reimported = await e2e.importPublicKey(jwk);
  assert.equal(reimported.algorithm.namedCurve, "P-256");
});

test("both parties derive the same session key", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  assert.equal(aliceKey.length, 32);
  assert.deepEqual(aliceKey, bobKey);
});

test("different roomCodes produce different session keys", async () => {
  const alice = await e2e.generateKeypair();
  const bob = await e2e.generateKeypair();
  const bobPub = await e2e.importPublicKey(
    await e2e.exportPublicKey(bob.publicKey),
  );

  const k1 = await e2e.deriveSessionKey(alice.privateKey, bobPub, "111111111");
  const k2 = await e2e.deriveSessionKey(alice.privateKey, bobPub, "222222222");

  assert.notDeepEqual(k1, k2);
});

test("different keypairs produce different session keys", async () => {
  const alice = await e2e.generateKeypair();
  const bob1 = await e2e.generateKeypair();
  const bob2 = await e2e.generateKeypair();
  const bob1Pub = await e2e.importPublicKey(
    await e2e.exportPublicKey(bob1.publicKey),
  );
  const bob2Pub = await e2e.importPublicKey(
    await e2e.exportPublicKey(bob2.publicKey),
  );

  const k1 = await e2e.deriveSessionKey(alice.privateKey, bob1Pub, ROOM_CODE);
  const k2 = await e2e.deriveSessionKey(alice.privateKey, bob2Pub, ROOM_CODE);

  assert.notDeepEqual(k1, k2);
});

test("deriveGrid is deterministic for a given session key", async () => {
  const { aliceKey } = await deriveBothSides();
  const g1 = await e2e.deriveGrid(aliceKey);
  const g2 = await e2e.deriveGrid(aliceKey);
  assert.deepEqual(g1, g2);
});

test("both parties derive identical grids", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const aliceGrid = await e2e.deriveGrid(aliceKey);
  const bobGrid = await e2e.deriveGrid(bobKey);
  assert.deepEqual(aliceGrid, bobGrid);
});

test("MITM causes grids to diverge", async () => {
  const alice = await e2e.generateKeypair();
  const bob = await e2e.generateKeypair();
  const mallory = await e2e.generateKeypair();

  const alicePubFromBob = await e2e.importPublicKey(
    await e2e.exportPublicKey(alice.publicKey),
  );
  const malloryPubFromBob = await e2e.importPublicKey(
    await e2e.exportPublicKey(mallory.publicKey),
  );

  const aliceKey = await e2e.deriveSessionKey(
    alice.privateKey,
    malloryPubFromBob,
    ROOM_CODE,
  );
  const bobKey = await e2e.deriveSessionKey(
    bob.privateKey,
    alicePubFromBob,
    ROOM_CODE,
  );

  const aliceGrid = await e2e.deriveGrid(aliceKey);
  const bobGrid = await e2e.deriveGrid(bobKey);
  assert.notDeepEqual(aliceGrid, bobGrid);
});

test("grid has 5 unique balls per column in range 1..99", async () => {
  const { aliceKey } = await deriveBothSides();
  const grid = await e2e.deriveGrid(aliceKey);

  for (const letter of ["B", "I", "N", "G", "O"]) {
    const col = grid[letter];
    assert.equal(col.length, 5, `${letter} column must have 5 balls`);
    assert.equal(
      new Set(col).size,
      5,
      `${letter} column must have unique balls`,
    );
    for (const n of col) {
      assert.ok(n >= 1 && n <= 99, `${letter} ball ${n} out of range`);
    }
  }
});

test("resolveBall maps position to letter+number", async () => {
  const grid = {
    B: [1, 2, 3, 4, 5],
    I: [16, 17, 18, 19, 20],
    N: [31, 32, 33, 34, 35],
    G: [46, 47, 48, 49, 50],
    O: [61, 62, 63, 64, 65],
  };
  assert.equal(e2e.resolveBall(grid, 0), "B1");
  assert.equal(e2e.resolveBall(grid, 4), "O61");
  assert.equal(e2e.resolveBall(grid, 7), "N32");
  assert.equal(e2e.resolveBall(grid, 24), "O65");
});

test("resolveBall rejects out-of-range positions", () => {
  const grid = {
    B: [1, 2, 3, 4, 5],
    I: [16, 17, 18, 19, 20],
    N: [31, 32, 33, 34, 35],
    G: [46, 47, 48, 49, 50],
    O: [61, 62, 63, 64, 65],
  };
  assert.throws(() => e2e.resolveBall(grid, -1));
  assert.throws(() => e2e.resolveBall(grid, 25));
  assert.throws(() => e2e.resolveBall(grid, 1.5));
  assert.throws(() => e2e.resolveBall(grid, "0"));
});

test("encrypt/decrypt roundtrip recovers plaintext", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const envelope = await e2e.encryptValue(
    aliceKey,
    "Alice Smith",
    ROOM_CODE,
    3,
    1,
    1,
  );
  const recovered = await e2e.decryptValue(bobKey, envelope, ROOM_CODE, 3);
  assert.equal(recovered, "Alice Smith");
});

test("encrypt with unicode plaintext roundtrips", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const envelope = await e2e.encryptValue(
    aliceKey,
    "naïve café — 日本語 🚀",
    ROOM_CODE,
    1,
    1,
    1,
  );
  const recovered = await e2e.decryptValue(bobKey, envelope, ROOM_CODE, 1);
  assert.equal(recovered, "naïve café — 日本語 🚀");
});

test("envelope contains v, seq, nonce, ct, tag as base64 strings", async () => {
  const { aliceKey } = await deriveBothSides();
  const env = await e2e.encryptValue(aliceKey, "hi", ROOM_CODE, 1, 1, 7);
  assert.equal(env.v, 1);
  assert.equal(env.seq, 7);
  assert.equal(typeof env.nonce, "string");
  assert.equal(typeof env.ct, "string");
  assert.equal(typeof env.tag, "string");
  // base64 nonce decodes to 12 bytes, tag to 16
  assert.equal(Buffer.from(env.nonce, "base64").length, 12);
  assert.equal(Buffer.from(env.tag, "base64").length, 16);
});

test("decrypt fails when room code differs (AAD mismatch)", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const envelope = await e2e.encryptValue(
    aliceKey,
    "secret",
    ROOM_CODE,
    1,
    1,
    1,
  );
  await assert.rejects(() =>
    e2e.decryptValue(bobKey, envelope, "999999999", 1),
  );
});

test("decrypt fails when field id differs (AAD mismatch)", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const envelope = await e2e.encryptValue(
    aliceKey,
    "secret",
    ROOM_CODE,
    1,
    1,
    1,
  );
  await assert.rejects(() => e2e.decryptValue(bobKey, envelope, ROOM_CODE, 2));
});

test("decrypt fails when seq is tampered in envelope", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const envelope = await e2e.encryptValue(
    aliceKey,
    "secret",
    ROOM_CODE,
    1,
    1,
    1,
  );
  const tampered = { ...envelope, seq: 2 };
  await assert.rejects(() => e2e.decryptValue(bobKey, tampered, ROOM_CODE, 1));
});

test("decrypt fails when ciphertext is tampered", async () => {
  const { aliceKey, bobKey } = await deriveBothSides();
  const envelope = await e2e.encryptValue(
    aliceKey,
    "secret",
    ROOM_CODE,
    1,
    1,
    1,
  );
  const ctBytes = Buffer.from(envelope.ct, "base64");
  ctBytes[0] ^= 0x01;
  const tampered = { ...envelope, ct: ctBytes.toString("base64") };
  await assert.rejects(() => e2e.decryptValue(bobKey, tampered, ROOM_CODE, 1));
});

test("decrypt fails when session keys differ (simulated MITM)", async () => {
  const alice = await e2e.generateKeypair();
  const bob = await e2e.generateKeypair();
  const mallory = await e2e.generateKeypair();

  const malloryPubFromAlice = await e2e.importPublicKey(
    await e2e.exportPublicKey(mallory.publicKey),
  );
  const alicePubFromBob = await e2e.importPublicKey(
    await e2e.exportPublicKey(alice.publicKey),
  );

  const aliceKey = await e2e.deriveSessionKey(
    alice.privateKey,
    malloryPubFromAlice,
    ROOM_CODE,
  );
  const bobKey = await e2e.deriveSessionKey(
    bob.privateKey,
    alicePubFromBob,
    ROOM_CODE,
  );

  const envelope = await e2e.encryptValue(
    aliceKey,
    "secret",
    ROOM_CODE,
    1,
    1,
    1,
  );
  await assert.rejects(() => e2e.decryptValue(bobKey, envelope, ROOM_CODE, 1));
});

test("PROTOCOL_VERSION is 1", () => {
  assert.equal(e2e.PROTOCOL_VERSION, 1);
});
