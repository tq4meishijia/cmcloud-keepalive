/**
 * V2.0 HmacSHA1 签名（对应上游 `protocol.py:69-122`）。
 *
 * 与上游的**唯一但关键**差异：canonical 查询串必须做 RFC3986 百分号编码。
 * 上游用 `f"{k}={v}"` 直接拼接，`: ` 保持原样，服务端判 `400 INVALID_PARAMETER`；
 * 改成 `urlencode(sorted(params))` 语义后服务端返回 200（见 docs/ANALYSIS.md §9 缺陷 B）。
 *
 * 签名链路：
 *   canonical    = sort(keys).map(k => enc(k) + "=" + enc(v)).join("&")
 *   hashStep     = sha256_hex(canonical)
 *   stringToSign = "POST\n" + enc(API_PATH + endpoint) + "\n" + hashStep
 *   signature    = hmac_sha1_hex("BC_SIGNATURE&" + SECRET_KEY, stringToSign)
 *
 * @module ecloud/signature
 */

import { ACCESS_KEY, API_PATH, HMAC_PREFIX, SECRET_KEY } from "./constants.js";

const UTF8_ENCODER = new TextEncoder();

/**
 * RFC3986 百分号编码，等价于 Python `urllib.parse.quote(value, safe="")`。
 *
 * `encodeURIComponent` 保留 `A-Za-z0-9-_.!~*'()`，其中 `!'()*` 不在 RFC3986
 * 的 unreserved 集合内，必须补转义；其余字符（含 `:/=&+?# ` 与中文）它已按
 * UTF-8 逐字节转成大写十六进制。
 *
 * @param {unknown} value 待编码值，非字符串会先转成字符串。
 * @returns {string} 编码结果。
 */
export function rfc3986Encode(value) {
  // 正则字面量写在函数体内：每次调用都是全新实例，不存在 lastIndex 跨调用残留。
  return encodeURIComponent(String(value)).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

/**
 * 断言入参是有效 Date。
 *
 * @param {unknown} value 被校验值。
 * @param {string} label 用于错误信息的参数名。
 * @returns {Date} 同一个 Date。
 */
function assertDate(value, label) {
  if (!(value instanceof Date) || Number.isNaN(value.getTime())) {
    throw new TypeError(`${label} 必须是有效的 Date 实例`);
  }
  return value;
}

/**
 * UTC+8 时间戳文本，格式 `YYYY-MM-DDTHH:MM:SSZ`（对应上游 `utc8_timestamp()`）。
 *
 * 语义是把 now 平移 +8 小时后按 UTC 格式化，**不依赖运行环境时区**。
 *
 * @param {Date} [now] 当前时间，默认取系统时间。
 * @returns {string} 例如 `2026-01-02T11:04:05Z`。
 */
export function utc8Timestamp(now = new Date()) {
  const shifted = new Date(assertDate(now, "now").getTime() + 8 * 3600 * 1000);
  return `${shifted.toISOString().slice(0, 19)}Z`;
}

/**
 * UTC+8 可读时间文本，格式 `YYYY-MM-DD HH:MM:SS`（对应上游 `utc8_now_str()`）。
 *
 * 用于日志与状态展示，不带时区后缀。
 *
 * @param {Date} [now] 当前时间，默认取系统时间。
 * @returns {string} 例如 `2026-01-02 11:04:05`。
 */
export function utc8NowText(now = new Date()) {
  const shifted = new Date(assertDate(now, "now").getTime() + 8 * 3600 * 1000);
  return shifted.toISOString().slice(0, 19).replace("T", " ");
}

/**
 * 生成签名 nonce（等价上游 `uuid.uuid4().hex`：32 位小写十六进制）。
 *
 * @param {number} [byteLength] 随机字节数，默认 16 → 32 个 hex 字符。
 * @returns {string} 十六进制 nonce。
 */
export function randomNonce(byteLength = 16) {
  if (!Number.isInteger(byteLength) || byteLength <= 0 || byteLength > 64) {
    throw new RangeError(`byteLength 必须是 1~64 的整数，收到 ${byteLength}`);
  }
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

/**
 * 组装参与签名的公共参数（不含 Signature 本身）。
 *
 * @param {object} options 参数。
 * @param {string} [options.nonce] 指定 nonce，缺省随机生成。
 * @param {string} [options.timestamp] 指定 UTC+8 时间戳，缺省由 now 推导。
 * @param {string} [options.accessToken] 访问令牌，非空时加入 AccessToken 参数。
 * @param {string} [options.accessKey] AccessKey，默认协议常量。
 * @returns {Record<string, string>} 待签名参数表。
 */
export function buildSignatureParams({ nonce, timestamp, accessToken = "", accessKey = ACCESS_KEY } = {}) {
  /** @type {Record<string, string>} */
  const params = {
    AccessKey: accessKey,
    SignatureMethod: "HmacSHA1",
    SignatureNonce: nonce || randomNonce(),
    SignatureVersion: "V2.0",
    Timestamp: timestamp || utc8Timestamp(),
  };
  if (accessToken) {
    params.AccessToken = accessToken;
  }
  return params;
}

/**
 * 生成 canonical 查询串：键升序，键与值都做 RFC3986 编码。
 *
 * @param {Record<string, unknown>} params 待签名参数表。
 * @returns {string} canonical 字符串。
 */
export function canonicalize(params) {
  if (!params || typeof params !== "object") {
    throw new TypeError("canonicalize 需要参数对象");
  }
  return Object.keys(params)
    .sort()
    .map((key) => `${rfc3986Encode(key)}=${rfc3986Encode(params[key])}`)
    .join("&");
}

/**
 * 字节数组转小写十六进制。
 *
 * @param {Uint8Array} bytes 输入字节。
 * @returns {string} 十六进制文本。
 */
export function bytesToHex(bytes) {
  let out = "";
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * SHA-256 摘要（小写十六进制）。
 *
 * @param {string} input 输入文本，按 UTF-8 编码。
 * @returns {Promise<string>} 十六进制摘要。
 */
export async function sha256Hex(input) {
  const digest = await crypto.subtle.digest("SHA-256", UTF8_ENCODER.encode(String(input)));
  return bytesToHex(new Uint8Array(digest));
}

/**
 * HmacSHA1（小写十六进制）。
 *
 * @param {string} key 密钥文本，按 UTF-8 编码。
 * @param {string} message 消息文本，按 UTF-8 编码。
 * @returns {Promise<string>} 十六进制签名。
 */
export async function hmacSha1Hex(key, message) {
  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    UTF8_ENCODER.encode(String(key)),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, UTF8_ENCODER.encode(String(message)));
  return bytesToHex(new Uint8Array(signature));
}

/**
 * 计算 V2.0 签名。
 *
 * @param {string} endpoint 形如 `/user/getSysTime`。
 * @param {string} canonical 由 {@link canonicalize} 生成的查询串。
 * @returns {Promise<string>} 40 位小写十六进制签名。
 */
export async function computeSignature(endpoint, canonical) {
  if (typeof endpoint !== "string" || endpoint === "") {
    throw new TypeError("computeSignature 需要非空 endpoint");
  }
  const hashStep = await sha256Hex(canonical);
  const stringToSign = `POST\n${rfc3986Encode(API_PATH + endpoint)}\n${hashStep}`;
  return hmacSha1Hex(HMAC_PREFIX + SECRET_KEY, stringToSign);
}

/**
 * 一次性生成签名所需的三段产物，供 `EcloudClient` 直接拼 URL。
 *
 * @param {object} options 参数。
 * @param {string} options.endpoint 业务端点。
 * @param {Date} [options.now] 当前时间。
 * @param {string} [options.accessToken] 访问令牌。
 * @param {string} [options.nonce] 指定 nonce（便于测试复现）。
 * @returns {Promise<{canonical: string, signature: string, query: string, nonce: string, timestamp: string}>}
 *   `query` 已是可直接拼到 URL 的完整查询串（含 Signature）。
 */
export async function buildSignedQuery({ endpoint, now = new Date(), accessToken = "", nonce } = {}) {
  const params = buildSignatureParams({ nonce, timestamp: utc8Timestamp(now), accessToken });
  const canonical = canonicalize(params);
  const signature = await computeSignature(endpoint, canonical);
  return {
    canonical,
    signature,
    query: `${canonical}&Signature=${signature}`,
    nonce: params.SignatureNonce,
    timestamp: params.Timestamp,
  };
}
