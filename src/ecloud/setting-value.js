/**
 * settingValue 解密（对应上游 `protocol.py:158-180`）。
 *
 * 用途：客户端 `settingValue.js` 里有一段 hex blob，用固定规则派生 AES-256-CBC 密钥加密，
 * 解开后是客户端的配置 JSON（服务器地址、功能开关等），属逆向辅助能力。
 * **不参与保活主链路**，仅在需要重新分析客户端配置时使用（需自备 hex blob）。
 *
 * 派生规则：
 *   key = SHA256("Ecloud-Computer-" + platform)   // 32 字节 → AES-256
 *   iv  = key[0..16]
 *   plain = AES-CBC-Decrypt(key, iv, hexToBytes(blob)) → 去 PKCS#7 → JSON
 *
 * @module ecloud/setting-value
 */

import { PLATFORM } from "./constants.js";
import { hexToBytes } from "./rsa.js";

/** 密钥派生盐前缀。 */
const SETTING_KEY_SALT = "Ecloud-Computer-";

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder();

/** AES 块大小。 */
const AES_BLOCK_SIZE = 16;

/**
 * 派生 AES-256 密钥与 IV。
 *
 * @param {string} [platform] 平台标识，默认协议常量 `win32`。
 * @returns {Promise<{key: Uint8Array, iv: Uint8Array}>} 32 字节密钥与 16 字节 IV（IV 为密钥前 16 字节）。
 */
export async function deriveSettingKey(platform = PLATFORM) {
  if (typeof platform !== "string" || platform === "") {
    throw new TypeError("platform 必须是非空字符串");
  }
  const digest = await crypto.subtle.digest("SHA-256", UTF8_ENCODER.encode(SETTING_KEY_SALT + platform));
  const key = new Uint8Array(digest);
  return { key, iv: key.slice(0, AES_BLOCK_SIZE) };
}

/**
 * 解密 settingValue hex blob。
 *
 * Web Crypto 的 AES-CBC 解密会自动剥离 PKCS#7 填充，并在填充非法时抛错，
 * 因此无需手写 unpad。
 *
 * @param {string} hexBlob 十六进制密文（来自客户端 settingValue.js）。
 * @param {string} [platform] 平台标识，默认 `win32`。
 * @returns {Promise<unknown>} 解析后的 JSON 对象。
 * @throws {TypeError} hex 非法时。
 * @throws {Error} 密文长度非法、填充非法或明文不是 JSON 时。
 */
export async function decryptSettingValue(hexBlob, platform = PLATFORM) {
  const cipherBytes = hexToBytes(hexBlob);
  if (cipherBytes.length === 0) {
    throw new Error("settingValue 密文为空");
  }
  if (cipherBytes.length % AES_BLOCK_SIZE !== 0) {
    throw new Error(
      `settingValue 密文长度 ${cipherBytes.length} 不是 ${AES_BLOCK_SIZE} 字节的整数倍`,
    );
  }

  const { key, iv } = await deriveSettingKey(platform);
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "AES-CBC" }, false, ["decrypt"]);

  let plain;
  try {
    plain = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, cryptoKey, cipherBytes);
  } catch (error) {
    throw new Error(
      `AES-CBC 解密失败（密钥或密文不匹配，PKCS#7 填充非法）：${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }

  const text = UTF8_DECODER.decode(plain);
  try {
    return JSON.parse(text);
  } catch {
    throw new Error(`settingValue 解密结果不是合法 JSON：${text.slice(0, 120)}`);
  }
}

/**
 * 供文档/调试使用：把派生密钥打印成 hex（不含任何用户信息）。
 *
 * @param {string} [platform] 平台标识。
 * @returns {Promise<string>} 32 字节密钥的 hex。
 */
export async function describeDerivedKey(platform = PLATFORM) {
  const { key } = await deriveSettingKey(platform);
  return Array.from(key, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
