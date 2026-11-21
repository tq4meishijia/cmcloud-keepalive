/**
 * RSA 实现测试。
 *
 * 全部用 Node `crypto` 做双向交叉验证：本实现加密 → Node 私钥解密；
 * Node 公钥加密 → 本实现私钥解密。另外锁死两条事实：
 *   - 上游内置公钥是占位符，`validatePublicKey` 必须返回 `ok:false`；
 *   - 单块 1024-bit 解密必须在 100ms 内（Workers CPU 预算）。
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { RSA_CHUNK_IN, RSA_CHUNK_OUT, UPSTREAM_RSA_PUBLIC_KEY_PEM } from "../src/ecloud/constants.js";
import {
  RSA_DECRYPT_FAILED,
  RSA_KEY_INVALID,
  RsaError,
  base64ToBytes,
  bigIntToBytes,
  bytesToBase64,
  bytesToBigInt,
  hexToBytes,
  modPow,
  parsePrivateKey,
  parsePublicKey,
  rsaDecryptPkcs1v15,
  rsaEncryptPkcs1v15,
  validatePrivateKey,
  validatePublicKey,
} from "../src/ecloud/rsa.js";

const RSA_PADDING = crypto.constants.RSA_PKCS1_PADDING;
const CIPHER_BLOCK = RSA_CHUNK_OUT; // 128 byte = 1024 bit
const PLAIN_BLOCK = RSA_CHUNK_IN; // 117 byte = 128 - 11

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
const PUBLIC_PEM = publicKey.export({ type: "spki", format: "pem" });
const PUBLIC_PKCS1_PEM = publicKey.export({ type: "pkcs1", format: "pem" });
const PRIVATE_PKCS1_PEM = privateKey.export({ type: "pkcs1", format: "pem" });
const PRIVATE_PKCS8_PEM = privateKey.export({ type: "pkcs8", format: "pem" });

const otherPair = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
const OTHER_PRIVATE_PEM = otherPair.privateKey.export({ type: "pkcs1", format: "pem" });

/**
 * 用 Node 私钥逐块解密。
 *
 * @param {string} base64 base64 密文。
 * @returns {Buffer} 明文。
 */
function nodeDecryptBlocks(base64) {
  const raw = Buffer.from(base64, "base64");
  const parts = [];
  for (let offset = 0; offset < raw.length; offset += CIPHER_BLOCK) {
    parts.push(
      crypto.privateDecrypt(
        { key: privateKey, padding: RSA_PADDING },
        raw.subarray(offset, offset + CIPHER_BLOCK),
      ),
    );
  }
  return Buffer.concat(parts);
}

/**
 * 用 Node 公钥逐块加密。
 *
 * @param {Buffer} buffer 明文。
 * @returns {string} base64 密文。
 */
function nodeEncryptBlocks(buffer) {
  const parts = [];
  for (let offset = 0; offset < buffer.length; offset += PLAIN_BLOCK) {
    parts.push(
      crypto.publicEncrypt(
        { key: publicKey, padding: RSA_PADDING },
        buffer.subarray(offset, offset + PLAIN_BLOCK),
      ),
    );
  }
  return Buffer.concat(parts).toString("base64");
}

test("base64 / hex 工具往返", () => {
  const bytes = new Uint8Array([0x00, 0x01, 0x7f, 0x80, 0xff]);
  assert.deepEqual(Array.from(base64ToBytes(bytesToBase64(bytes))), Array.from(bytes));
  assert.deepEqual(Array.from(hexToBytes("00017f80ff")), Array.from(bytes));
  assert.deepEqual(Array.from(hexToBytes("0x00 01 7F 80 FF")), Array.from(bytes));
  assert.deepEqual(Array.from(base64ToBytes("")), []);
  assert.deepEqual(Array.from(hexToBytes("")), []);
  assert.throws(() => base64ToBytes("abc"), (error) => error.code === RSA_KEY_INVALID);
  assert.throws(() => hexToBytes("abc"), TypeError);
  assert.throws(() => hexToBytes("zz"), TypeError);
});

test("bytesToBigInt / bigIntToBytes 往返与越界", () => {
  const value = bytesToBigInt(new Uint8Array([0x01, 0x02, 0x03]));
  assert.equal(value, 0x010203n);
  assert.deepEqual(Array.from(bigIntToBytes(value, 4)), [0x00, 0x01, 0x02, 0x03]);
  assert.deepEqual(Array.from(bigIntToBytes(value, 3)), [0x01, 0x02, 0x03]);
  assert.throws(() => bigIntToBytes(value, 2), RangeError);
  assert.throws(() => bigIntToBytes(-1n, 2), RangeError);
  assert.throws(() => bigIntToBytes(1, 2), TypeError);
});

test("modPow 正确性（含 0 指数与负底数归一）", () => {
  assert.equal(modPow(2n, 10n, 1000n), 24n);
  assert.equal(modPow(5n, 0n, 7n), 1n);
  assert.equal(modPow(0n, 0n, 7n), 1n);
  assert.equal(modPow(-1n, 3n, 5n), 4n);
  assert.equal(modPow(4n, 13n, 497n), 445n);
  assert.throws(() => modPow(2n, 2n, 0n), RangeError);
  assert.throws(() => modPow(2n, -1n, 7n), RangeError);
  assert.throws(() => modPow(2, 2n, 7n), TypeError);
});

test("解析 1024-bit SPKI 公钥", () => {
  const key = parsePublicKey(PUBLIC_PEM);
  assert.equal(key.bits, 1024);
  assert.equal(key.k, 128);
  assert.equal(key.e, 65537n);
  assert.match(key.label, /PUBLIC KEY/);
  // 协议分块常量必须与 1024-bit 模数推导结果一致
  assert.equal(key.k, RSA_CHUNK_OUT);
  assert.equal(key.k - 11, RSA_CHUNK_IN);
});

test("解析 PKCS#1 公钥（RSA PUBLIC KEY）", () => {
  const key = parsePublicKey(PUBLIC_PKCS1_PEM);
  assert.equal(key.bits, 1024);
  assert.equal(key.e, 65537n);
});

test("解析 PKCS#1 与 PKCS#8 私钥并得到相同 n/d", () => {
  const pkcs1 = parsePrivateKey(PRIVATE_PKCS1_PEM);
  const pkcs8 = parsePrivateKey(PRIVATE_PKCS8_PEM);
  assert.equal(pkcs1.n, pkcs8.n);
  assert.equal(pkcs1.d, pkcs8.d);
  assert.equal(pkcs1.bits, 1024);
  assert.match(pkcs1.label, /RSA PRIVATE KEY/);
  assert.match(pkcs8.label, /PRIVATE KEY/);
});

test("validatePublicKey 对上游占位符必须返回 ok:false", () => {
  const result = validatePublicKey(UPSTREAM_RSA_PUBLIC_KEY_PEM);
  assert.equal(result.ok, false);
  assert.equal(result.bits, null);
  assert.match(result.error, /长度不匹配/);
  assert.match(result.error, /282/);
});

test("validatePrivateKey 对占位符公钥返回 ok:false", () => {
  const result = validatePrivateKey(UPSTREAM_RSA_PUBLIC_KEY_PEM);
  assert.equal(result.ok, false);
  assert.equal(result.bits, null);
});

test("非法 PEM / 结构性错误抛 RSA_KEY_INVALID", () => {
  const cases = [
    "",
    "   ",
    "not a pem",
    "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
    "-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----",
    // 把私钥塞进公钥位置，应被显式拒绝
    PRIVATE_PKCS1_PEM,
  ];
  for (const pem of cases) {
    assert.throws(
      () => parsePublicKey(pem),
      (error) => error instanceof RsaError && error.code === RSA_KEY_INVALID,
      `应当拒绝：${JSON.stringify(pem.slice(0, 40))}`,
    );
  }
  assert.throws(
    () => parsePrivateKey(PUBLIC_PEM),
    (error) => error.code === RSA_KEY_INVALID,
  );
});

test("加密 300 字节（3 块）→ Node 私钥解密与原文相等", () => {
  const payload = crypto.randomBytes(300);
  const cipherBase64 = rsaEncryptPkcs1v15(payload, PUBLIC_PEM);

  const raw = Buffer.from(cipherBase64, "base64");
  assert.equal(raw.length, 3 * CIPHER_BLOCK);

  const decrypted = nodeDecryptBlocks(cipherBase64);
  assert.equal(decrypted.length, 300);
  assert.equal(decrypted.equals(payload), true);
});

test("117 字节（单块上限）能被单块加密", () => {
  const payload = crypto.randomBytes(117);
  const cipherBase64 = rsaEncryptPkcs1v15(payload, PUBLIC_PEM);
  assert.equal(Buffer.from(cipherBase64, "base64").length, CIPHER_BLOCK);
  assert.equal(nodeDecryptBlocks(cipherBase64).equals(payload), true);
});

test("反向：Node 公钥加密 → 本实现私钥解密（PKCS#8）", () => {
  const payload = crypto.randomBytes(300);
  const cipherBase64 = nodeEncryptBlocks(payload);
  const decrypted = rsaDecryptPkcs1v15(cipherBase64, PRIVATE_PKCS8_PEM);
  assert.equal(Buffer.from(decrypted).equals(payload), true);
});

test("反向：Node 公钥加密 → 本实现私钥解密（PKCS#1）", () => {
  const payload = Buffer.from('{"body":{"uptimeSeconds":42}}', "utf8");
  const cipherBase64 = nodeEncryptBlocks(payload);
  const decrypted = rsaDecryptPkcs1v15(cipherBase64, PRIVATE_PKCS1_PEM);
  assert.equal(Buffer.from(decrypted).toString("utf8"), '{"body":{"uptimeSeconds":42}}');
});

test("已解析的密钥对象可复用（避免重复解析 PEM）", () => {
  const parsedPublic = parsePublicKey(PUBLIC_PEM);
  const parsedPrivate = parsePrivateKey(PRIVATE_PKCS1_PEM);
  const payload = Buffer.from("hello-cloudpc", "utf8");
  const cipherBase64 = rsaEncryptPkcs1v15(payload, parsedPublic);
  const decrypted = rsaDecryptPkcs1v15(cipherBase64, parsedPrivate);
  assert.equal(Buffer.from(decrypted).toString("utf8"), "hello-cloudpc");
});

test("空明文加密被拒绝", () => {
  assert.throws(
    () => rsaEncryptPkcs1v15(new Uint8Array(0), PUBLIC_PEM),
    (error) => error.code === RSA_KEY_INVALID,
  );
});

test("密文长度不是 128 的整数倍 → RSA_DECRYPT_FAILED", () => {
  assert.throws(
    () => rsaDecryptPkcs1v15("AAAA", PRIVATE_PKCS1_PEM),
    (error) => error.code === RSA_DECRYPT_FAILED,
  );
  assert.throws(
    () => rsaDecryptPkcs1v15(new Uint8Array(0), PRIVATE_PKCS1_PEM),
    (error) => error.code === RSA_DECRYPT_FAILED,
  );
});

test("全零密文块 → 填充头非法 → RSA_DECRYPT_FAILED", () => {
  const zeroBlock = new Uint8Array(CIPHER_BLOCK);
  assert.throws(
    () => rsaDecryptPkcs1v15(zeroBlock, PRIVATE_PKCS1_PEM),
    (error) => error.code === RSA_DECRYPT_FAILED && /填充头非法/.test(error.message),
  );
});

test("错误的私钥无法解密别人的密文", () => {
  const payload = crypto.randomBytes(64);
  const cipherBase64 = rsaEncryptPkcs1v15(payload, PUBLIC_PEM);
  assert.throws(() =>
    rsaDecryptPkcs1v15(cipherBase64, OTHER_PRIVATE_PEM),
  );
});

test("性能：单块 1024-bit 私钥解密 < 100ms", () => {
  const payload = crypto.randomBytes(PLAIN_BLOCK);
  const cipherBase64 = rsaEncryptPkcs1v15(payload, PUBLIC_PEM);
  const parsedPrivate = parsePrivateKey(PRIVATE_PKCS1_PEM);

  // 预热，避免 JIT 冷启动计入
  rsaDecryptPkcs1v15(cipherBase64, parsedPrivate);

  const startedAt = performance.now();
  const decrypted = rsaDecryptPkcs1v15(cipherBase64, parsedPrivate);
  const elapsed = performance.now() - startedAt;

  assert.equal(Buffer.from(decrypted).equals(payload), true);
  assert.ok(elapsed < 100, `单块解密耗时 ${elapsed.toFixed(2)}ms，超过 100ms 预算`);
});
