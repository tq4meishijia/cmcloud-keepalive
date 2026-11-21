/**
 * settingValue 解密测试。
 *
 * fixture 用 Node `crypto` 按同一条派生规则（SHA256("Ecloud-Computer-"+platform)，iv=key[:16]）
 * 现场加密，避免仓库里出现任何真实客户端数据。
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { decryptSettingValue, deriveSettingKey, describeDerivedKey } from "../src/ecloud/setting-value.js";

const PLATFORM = "win32";

/**
 * 按协议规则派生密钥/IV。
 *
 * @param {string} platform 平台标识。
 * @returns {{key: Buffer, iv: Buffer}} 密钥与 IV。
 */
function nodeDerive(platform) {
  const key = crypto.createHash("sha256").update(`Ecloud-Computer-${platform}`, "utf8").digest();
  return { key, iv: key.subarray(0, 16) };
}

/**
 * 用 Node crypto 造一个 hex 密文 fixture（PKCS#7 填充，与 Web Crypto 一致）。
 *
 * @param {unknown} value 待加密对象。
 * @param {string} [platform] 平台标识。
 * @returns {string} hex 密文。
 */
function encryptFixture(value, platform = PLATFORM) {
  const { key, iv } = nodeDerive(platform);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const plaintext = Buffer.from(JSON.stringify(value), "utf8");
  return Buffer.concat([cipher.update(plaintext), cipher.final()]).toString("hex");
}

test("deriveSettingKey 产出 32 字节 AES-256 密钥，IV 为密钥前 16 字节", async () => {
  const { key, iv } = await deriveSettingKey(PLATFORM);
  assert.equal(key.length, 32);
  assert.equal(iv.length, 16);
  assert.deepEqual(Array.from(iv), Array.from(key.subarray(0, 16)));
  assert.equal(await describeDerivedKey(PLATFORM), Buffer.from(key).toString("hex"));
  assert.equal(
    Buffer.from(key).toString("hex"),
    nodeDerive(PLATFORM).key.toString("hex"),
  );
});

test("解密 Node 造的 fixture，与原文对象相等", async () => {
  const original = {
    serverUrl: "https://example.invalid/cem",
    feature: { keepalive: true, retry: 3 },
    note: "含中文的配置值",
    list: [1, 2, 3],
  };
  const hex = encryptFixture(original);
  const decrypted = await decryptSettingValue(hex);
  assert.deepEqual(decrypted, original);
});

test("不同 platform 派生不同密钥，跨平台解密必然失败", async () => {
  const hex = encryptFixture({ hello: "world" }, "linux");
  await assert.rejects(() => decryptSettingValue(hex, "win32"));
});

test("hex 非法时抛 TypeError", async () => {
  await assert.rejects(() => decryptSettingValue("zz"), TypeError);
  await assert.rejects(() => decryptSettingValue("abc"), TypeError);
});

test("密文长度非法时抛错并给出长度", async () => {
  await assert.rejects(() => decryptSettingValue(""), /密文为空/);
  await assert.rejects(() => decryptSettingValue("00".repeat(17)), /不是 16 字节的整数倍/);
});

test("密文被篡改时抛错（填充或 JSON 非法）", async () => {
  const hex = encryptFixture({ a: 1 });
  const bytes = Buffer.from(hex, "hex");
  // 篡改最后一个字节：几乎必然破坏 PKCS#7 填充
  bytes[bytes.length - 1] ^= 0xff;
  await assert.rejects(() => decryptSettingValue(bytes.toString("hex")));
});

test("明文不是 JSON 时抛错", async () => {
  const { key, iv } = nodeDerive(PLATFORM);
  const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
  const hex = Buffer.concat([
    cipher.update(Buffer.from("not-json-at-all", "utf8")),
    cipher.final(),
  ]).toString("hex");
  await assert.rejects(() => decryptSettingValue(hex), /不是合法 JSON/);
});
