/**
 * 零依赖 RSA（PKCS#1 v1.5）实现，对应上游 `protocol.py:125-155`。
 *
 * 为什么必须自己写：Workers 的 Web Crypto **不支持 RSAES-PKCS1-v1_5 加密**
 * （`crypto.subtle` 只有 RSA-OAEP），而云电脑网关只认 PKCS#1 v1.5。引入
 * node-forge / jsrsasign 会给 Workers 带来数百 KB 打包体积与兼容风险，
 * 因此这里用 `BigInt` 实现模幂 + 手工 DER 解析 + 手工填充，约 300 行、零依赖。
 *
 * 覆盖能力：
 *   - PEM/DER 解析：SPKI(`PUBLIC KEY`)、PKCS#1(`RSA PUBLIC KEY` / `RSA PRIVATE KEY`)、PKCS#8(`PRIVATE KEY`)
 *   - 分块加解密：1024-bit 模数下明文 117 B/块、密文 128 B/块
 *   - `validatePublicKey` / `validatePrivateKey`：不抛异常，供 `/api/diagnose` 使用
 *
 * 错误码（写进 `RsaError.code`）：
 *   - `RSA_KEY_INVALID`：PEM/DER 结构非法、密钥长度不支持、把私钥当公钥用……
 *   - `RSA_DECRYPT_FAILED`：密文长度错误、填充非法、数值越界
 *
 * @module ecloud/rsa
 */

/** 密钥不可解析。 */
export const RSA_KEY_INVALID = "RSA_KEY_INVALID";

/** 解密失败（密文或填充非法）。 */
export const RSA_DECRYPT_FAILED = "RSA_DECRYPT_FAILED";

/** PKCS#1 v1.5 填充串的最小长度（EM = 00 02 PS 00 M，PS >= 8）。 */
const MIN_PS_LENGTH = 8;

/** DER tag：INTEGER。 */
const TAG_INTEGER = 0x02;

/** DER tag：BIT STRING。 */
const TAG_BIT_STRING = 0x03;

/** DER tag：OCTET STRING。 */
const TAG_OCTET_STRING = 0x04;

/** DER tag：SEQUENCE。 */
const TAG_SEQUENCE = 0x30;

const UTF8_ENCODER = new TextEncoder();

/** RSA 相关错误，带稳定的 `code` 便于上层翻译成人话。 */
export class RsaError extends Error {
  /**
   * @param {string} code `RSA_KEY_INVALID` 或 `RSA_DECRYPT_FAILED`。
   * @param {string} message 可诊断的中文错误信息。
   * @param {Error} [cause] 原始异常。
   */
  constructor(code, message, cause) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "RsaError";
    this.code = code;
  }
}

// ---------------------------------------------------------------------------
// 二进制工具
// ---------------------------------------------------------------------------

/**
 * base64 → 字节数组。
 *
 * @param {string} text base64 文本（允许换行/空白）。
 * @param {string} [code] 失败时抛出的错误码，默认 `RSA_KEY_INVALID`。
 * @returns {Uint8Array} 解码结果。
 */
export function base64ToBytes(text, code = RSA_KEY_INVALID) {
  const normalized = String(text).replace(/\s+/g, "");
  if (normalized === "") return new Uint8Array(0);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(normalized) || normalized.length % 4 !== 0) {
    throw new RsaError(code, "base64 文本格式非法（长度必须是 4 的整数倍，且只含 A-Za-z0-9+/=）");
  }
  let binary;
  try {
    binary = atob(normalized);
  } catch (error) {
    throw new RsaError(code, `base64 解码失败：${error instanceof Error ? error.message : String(error)}`);
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * 字节数组 → base64（分片拼接，避免大数组触发参数上限）。
 *
 * @param {Uint8Array} bytes 输入字节。
 * @returns {string} base64 文本。
 */
export function bytesToBase64(bytes) {
  const chunkSize = 0x8000;
  let binary = "";
  for (let offset = 0; offset < bytes.length; offset += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
  }
  return btoa(binary);
}

/**
 * 十六进制 → 字节数组（供 settingValue 解密使用）。
 *
 * @param {string} hex 十六进制文本，允许空白与 `0x` 前缀。
 * @returns {Uint8Array} 解码结果。
 */
export function hexToBytes(hex) {
  const normalized = String(hex).trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (normalized === "") return new Uint8Array(0);
  if (normalized.length % 2 !== 0) {
    throw new TypeError(`十六进制字符串长度 ${normalized.length} 不是偶数`);
  }
  if (/[^0-9a-fA-F]/.test(normalized)) {
    throw new TypeError("十六进制字符串含非 0-9a-f 字符");
  }
  const bytes = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * 把多种二进制形态统一成 Uint8Array。
 *
 * @param {Uint8Array|ArrayBuffer|ArrayBufferView|string} data 输入数据。
 * @returns {Uint8Array} 字节视图。
 */
function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (typeof data === "string") return UTF8_ENCODER.encode(data);
  throw new TypeError("RSA 数据必须是 Uint8Array / ArrayBuffer / 字符串");
}

// ---------------------------------------------------------------------------
// 极简 DER reader（仅支持 definite length）
// ---------------------------------------------------------------------------

/**
 * 读取一个 TLV 头。
 *
 * 支持短格式长度与 `0x81/0x82/0x83/0x84` 长格式长度；indefinite length（`0x80`）不支持。
 *
 * @param {Uint8Array} bytes DER 字节。
 * @param {number} offset 起始偏移。
 * @returns {{tag: number, length: number, valueOffset: number, headerLength: number, end: number}} TLV 描述。
 */
export function readTLV(bytes, offset = 0) {
  if (offset < 0 || offset + 2 > bytes.length) {
    throw new RsaError(RSA_KEY_INVALID, `DER 偏移 ${offset} 越界（总长 ${bytes.length}）`);
  }
  const tag = bytes[offset];
  let cursor = offset + 1;
  let length = bytes[cursor];
  cursor += 1;
  if (length & 0x80) {
    const byteCount = length & 0x7f;
    if (byteCount === 0) {
      throw new RsaError(RSA_KEY_INVALID, "不支持 DER indefinite length（0x80）");
    }
    if (byteCount > 4) {
      throw new RsaError(RSA_KEY_INVALID, `DER 长度字段过长（${byteCount} 字节）`);
    }
    if (cursor + byteCount > bytes.length) {
      throw new RsaError(RSA_KEY_INVALID, "DER 长度字段被截断");
    }
    length = 0;
    for (let i = 0; i < byteCount; i += 1) {
      length = (length << 8) | bytes[cursor];
      cursor += 1;
    }
  }
  const valueOffset = cursor;
  const end = valueOffset + length;
  if (end > bytes.length) {
    throw new RsaError(
      RSA_KEY_INVALID,
      `DER 内容越界：节点声明 ${length} 字节，实际只剩 ${bytes.length - valueOffset} 字节`,
    );
  }
  return { tag, length, valueOffset, headerLength: cursor - offset, end };
}

/**
 * 读取一个节点的全部子节点。
 *
 * @param {Uint8Array} bytes DER 字节。
 * @param {{valueOffset: number, end: number}} parent 父节点。
 * @returns {Array<ReturnType<typeof readTLV>>} 子节点列表。
 */
function readChildren(bytes, parent) {
  const nodes = [];
  let cursor = parent.valueOffset;
  while (cursor < parent.end) {
    const tlv = readTLV(bytes, cursor);
    nodes.push(tlv);
    cursor = tlv.end;
  }
  return nodes;
}

/**
 * 读取 INTEGER 节点的值。
 *
 * @param {Uint8Array} bytes DER 字节。
 * @param {ReturnType<typeof readTLV>} node 节点。
 * @returns {bigint} 无符号大整数（DER 用前导 0x00 表示正数，这里忽略符号位）。
 */
function readInteger(bytes, node) {
  if (node.tag !== TAG_INTEGER) {
    throw new RsaError(RSA_KEY_INVALID, `期望 INTEGER(0x02)，实际 tag=0x${node.tag.toString(16)}`);
  }
  if (node.length === 0) {
    throw new RsaError(RSA_KEY_INVALID, "INTEGER 内容为空");
  }
  return bytesToBigInt(bytes.subarray(node.valueOffset, node.end));
}

// ---------------------------------------------------------------------------
// PEM / DER 解析
// ---------------------------------------------------------------------------

/**
 * 归一化 PEM 文本：去首尾空白，并把字面量 `\n` 还原成换行。
 *
 * 后者是为了兼容把多行 secret 塞进单一环境变量的场景
 * （`wrangler secret put` 支持多行，但 `wrangler.toml` 的 vars 不支持）。
 *
 * @param {string} pem 原始文本。
 * @returns {string} 归一化文本。
 */
function normalizePem(pem) {
  const text = String(pem).trim();
  if (!text.includes("\n") && text.includes("\\n")) {
    return text.replace(/\\n/g, "\n");
  }
  return text;
}

/**
 * PEM → DER，并返回头部标签（`PUBLIC KEY` / `RSA PRIVATE KEY` 等）。
 *
 * @param {string} pem PEM 文本。
 * @returns {{der: Uint8Array, label: string}} DER 与标签。
 */
function pemToDer(pem) {
  if (typeof pem !== "string" || pem.trim() === "") {
    throw new RsaError(RSA_KEY_INVALID, "PEM 为空：未配置密钥或环境变量只含空白");
  }
  const text = normalizePem(pem);
  const match = /-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/.exec(text);
  if (!match) {
    throw new RsaError(
      RSA_KEY_INVALID,
      "PEM 缺少 -----BEGIN ...----- / -----END ...----- 头尾（公钥示例：-----BEGIN PUBLIC KEY-----）",
    );
  }
  const label = match[1].trim();
  const body = match[2].replace(/\s+/g, "");
  if (body === "") {
    throw new RsaError(RSA_KEY_INVALID, `PEM 正文为空（标签 ${label}）`);
  }
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body)) {
    throw new RsaError(RSA_KEY_INVALID, `PEM 正文含非法 base64 字符（标签 ${label}）`);
  }
  const der = base64ToBytes(body);
  if (der.length < 16) {
    throw new RsaError(RSA_KEY_INVALID, `DER 过短（${der.length} 字节），不是有效密钥`);
  }
  return { der, label };
}

/**
 * 解析 DER 根节点并强校验总长度。
 *
 * 长度强校验是识破上游占位符的关键：占位符外层 SEQUENCE 声明到第 163 字节，
 * 而实际有 282 字节 → 在这里被拒。
 *
 * @param {Uint8Array} der DER 字节。
 * @returns {ReturnType<typeof readTLV>} 根节点。
 */
function parseDerRoot(der) {
  const root = readTLV(der, 0);
  if (root.tag !== TAG_SEQUENCE) {
    throw new RsaError(RSA_KEY_INVALID, `DER 根节点不是 SEQUENCE（tag=0x${root.tag.toString(16)}）`);
  }
  if (root.end !== der.length) {
    throw new RsaError(
      RSA_KEY_INVALID,
      `DER 长度不匹配：外层 SEQUENCE 只声明到第 ${root.end} 字节，实际共 ${der.length} 字节` +
        "（疑似上游占位符，或 base64 被截断/追加）",
    );
  }
  return root;
}

/**
 * 校验模数/指数并推导位长与分块长度。
 *
 * @param {bigint} n 模数。
 * @param {bigint} e 公钥指数。
 * @returns {{n: bigint, e: bigint, bits: number, k: number}} 公钥参数。
 */
function buildPublicKey(n, e) {
  if (n <= 0n) throw new RsaError(RSA_KEY_INVALID, "模数 n 必须为正整数");
  if (e <= 0n) throw new RsaError(RSA_KEY_INVALID, "公钥指数 e 必须为正整数");
  if (e % 2n === 0n) throw new RsaError(RSA_KEY_INVALID, "公钥指数 e 必须为奇数");
  const bits = n.toString(2).length;
  if (bits < 512 || bits > 4096) {
    throw new RsaError(RSA_KEY_INVALID, `不支持 ${bits} bit 的 RSA 密钥（支持 512~4096 bit）`);
  }
  return { n, e, bits, k: Math.ceil(bits / 8) };
}

/**
 * 统一入口：接受 PEM 字符串或 DER 字节，产出 `{der, label}`。
 *
 * @param {string|Uint8Array} input PEM 或 DER。
 * @param {string} kind `公钥` / `私钥`，仅用于错误信息。
 * @returns {{der: Uint8Array, label: string}} DER 与标签。
 */
function toDer(input, kind) {
  if (typeof input === "string") return pemToDer(input);
  if (input instanceof Uint8Array) return { der: input, label: `DER(${kind})` };
  throw new RsaError(RSA_KEY_INVALID, `${kind}必须是 PEM 字符串或 Uint8Array`);
}

/**
 * 解析 RSA 公钥（支持 SPKI 与 PKCS#1）。
 *
 * @param {string|Uint8Array} input PEM 或 DER。
 * @returns {{n: bigint, e: bigint, bits: number, k: number, label: string}} 公钥参数。
 * @throws {RsaError} 结构非法时抛 `RSA_KEY_INVALID`。
 */
export function parsePublicKey(input) {
  const { der, label } = toDer(input, "公钥");
  if (/PRIVATE/i.test(label)) {
    throw new RsaError(RSA_KEY_INVALID, `传入的是私钥 PEM（${label}），公钥位置请填 -----BEGIN PUBLIC KEY-----`);
  }
  const root = parseDerRoot(der);
  const kids = readChildren(der, root);
  if (kids.length === 0) {
    throw new RsaError(RSA_KEY_INVALID, "公钥 DER 的 SEQUENCE 为空");
  }

  let n;
  let e;
  if (kids[0].tag === TAG_SEQUENCE) {
    // SubjectPublicKeyInfo: SEQUENCE { AlgorithmIdentifier, BIT STRING }
    if (kids.length < 2 || kids[1].tag !== TAG_BIT_STRING) {
      throw new RsaError(RSA_KEY_INVALID, "SPKI 公钥缺少 BIT STRING 节点");
    }
    const bitString = kids[1];
    if (bitString.length < 2) {
      throw new RsaError(RSA_KEY_INVALID, "SPKI 的 BIT STRING 内容过短");
    }
    if (der[bitString.valueOffset] !== 0x00) {
      throw new RsaError(RSA_KEY_INVALID, "SPKI 的 BIT STRING 存在未使用位，不是合法 RSA 公钥");
    }
    const innerRoot = readTLV(der, bitString.valueOffset + 1);
    if (innerRoot.tag !== TAG_SEQUENCE) {
      throw new RsaError(RSA_KEY_INVALID, "SPKI 内层不是 RSAPublicKey SEQUENCE");
    }
    if (innerRoot.end !== bitString.end) {
      throw new RsaError(RSA_KEY_INVALID, "SPKI 的 BIT STRING 内层长度不匹配");
    }
    const inner = readChildren(der, innerRoot);
    if (inner.length < 2) {
      throw new RsaError(RSA_KEY_INVALID, "RSAPublicKey 缺少 n 或 e");
    }
    n = readInteger(der, inner[0]);
    e = readInteger(der, inner[1]);
  } else if (kids[0].tag === TAG_INTEGER) {
    // PKCS#1 RSAPublicKey: SEQUENCE { n, e }
    if (kids.length < 2) {
      throw new RsaError(RSA_KEY_INVALID, "PKCS#1 公钥缺少 e");
    }
    n = readInteger(der, kids[0]);
    e = readInteger(der, kids[1]);
  } else {
    throw new RsaError(
      RSA_KEY_INVALID,
      `无法识别的公钥结构（首个子节点 tag=0x${kids[0].tag.toString(16)}）`,
    );
  }
  return { ...buildPublicKey(n, e), label };
}

/**
 * 解析 RSA 私钥（支持 PKCS#1 与 PKCS#8）。
 *
 * 只提取 n/e/d —— PKCS#1 v1.5 解密不需要 CRT 参数。
 *
 * @param {string|Uint8Array} input PEM 或 DER。
 * @returns {{n: bigint, e: bigint, d: bigint, bits: number, k: number, label: string}} 私钥参数。
 * @throws {RsaError} 结构非法时抛 `RSA_KEY_INVALID`。
 */
export function parsePrivateKey(input) {
  const { der, label } = toDer(input, "私钥");
  if (/PUBLIC/i.test(label)) {
    throw new RsaError(RSA_KEY_INVALID, `传入的是公钥 PEM（${label}），私钥位置请填 -----BEGIN PRIVATE KEY-----`);
  }
  const root = parseDerRoot(der);
  const kids = readChildren(der, root);
  if (kids.length === 0) {
    throw new RsaError(RSA_KEY_INVALID, "私钥 DER 的 SEQUENCE 为空");
  }

  let sequenceDer = der;
  let sequence = root;
  if (kids.length >= 3 && kids[1].tag === TAG_SEQUENCE && kids[2].tag === TAG_OCTET_STRING) {
    // PKCS#8 PrivateKeyInfo: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING, ... }
    const octet = kids[2];
    sequenceDer = der.subarray(octet.valueOffset, octet.end);
    sequence = parseDerRoot(sequenceDer);
  } else if (kids[0].tag !== TAG_INTEGER) {
    throw new RsaError(
      RSA_KEY_INVALID,
      `无法识别的私钥结构（首个子节点 tag=0x${kids[0].tag.toString(16)}）`,
    );
  }

  const parts = readChildren(sequenceDer, sequence);
  if (parts.length < 4) {
    throw new RsaError(
      RSA_KEY_INVALID,
      `RSAPrivateKey 字段不足（${parts.length} 个），至少需要 version/n/e/d`,
    );
  }
  const publicKey = buildPublicKey(readInteger(sequenceDer, parts[1]), readInteger(sequenceDer, parts[2]));
  const d = readInteger(sequenceDer, parts[3]);
  if (d <= 0n || d >= publicKey.n) {
    throw new RsaError(RSA_KEY_INVALID, "私钥指数 d 越界（必须满足 0 < d < n）");
  }
  return { ...publicKey, d, label };
}

/**
 * 校验公钥可解析性，**不抛异常**。
 *
 * @param {string|Uint8Array} pem PEM 或 DER。
 * @returns {{ok: boolean, bits: number|null, error: string|null}} 校验结果。
 */
export function validatePublicKey(pem) {
  try {
    const key = parsePublicKey(pem);
    return { ok: true, bits: key.bits, error: null };
  } catch (error) {
    return { ok: false, bits: null, error: errorMessage(error) };
  }
}

/**
 * 校验私钥可解析性，**不抛异常**。
 *
 * @param {string|Uint8Array} pem PEM 或 DER。
 * @returns {{ok: boolean, bits: number|null, error: string|null}} 校验结果。
 */
export function validatePrivateKey(pem) {
  try {
    const key = parsePrivateKey(pem);
    return { ok: true, bits: key.bits, error: null };
  } catch (error) {
    return { ok: false, bits: null, error: errorMessage(error) };
  }
}

/**
 * 把任意异常转成可读文本。
 *
 * @param {unknown} error 异常。
 * @returns {string} 文本。
 */
function errorMessage(error) {
  if (error instanceof Error) return error.message;
  return String(error);
}

// ---------------------------------------------------------------------------
// BigInt 数学
// ---------------------------------------------------------------------------

/**
 * 大端字节数组 → BigInt。
 *
 * @param {Uint8Array} bytes 大端字节。
 * @returns {bigint} 整数。
 */
export function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

/**
 * BigInt → 定长大端字节数组（左侧补 0x00）。
 *
 * @param {bigint} value 整数。
 * @param {number} length 目标字节长度。
 * @returns {Uint8Array} 定长字节数组。
 * @throws {RangeError} 数值放不进目标长度时。
 */
export function bigIntToBytes(value, length) {
  if (typeof value !== "bigint") throw new TypeError("bigIntToBytes 只接受 BigInt");
  if (value < 0n) throw new RangeError("bigIntToBytes 不支持负数");
  if (!Number.isInteger(length) || length <= 0) throw new RangeError(`length 必须是正整数，收到 ${length}`);
  const bytes = new Uint8Array(length);
  let rest = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    bytes[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  if (rest !== 0n) {
    throw new RangeError(`数值 0x${value.toString(16)} 超出 ${length} 字节`);
  }
  return bytes;
}

/**
 * 模幂 `base^exponent mod modulus`，从指数最高位开始的 square-and-multiply。
 *
 * @param {bigint} base 底数。
 * @param {bigint} exponent 指数（非负）。
 * @param {bigint} modulus 模数（正）。
 * @returns {bigint} 结果，范围 `[0, modulus)`。
 */
export function modPow(base, exponent, modulus) {
  if (typeof base !== "bigint" || typeof exponent !== "bigint" || typeof modulus !== "bigint") {
    throw new TypeError("modPow 的三个参数都必须是 BigInt");
  }
  if (modulus <= 0n) throw new RangeError("modPow 的 modulus 必须为正整数");
  if (exponent < 0n) throw new RangeError("modPow 不支持负指数");
  let normalized = base % modulus;
  if (normalized < 0n) normalized += modulus;
  if (exponent === 0n) return 1n % modulus;

  let result = 1n;
  const bits = exponent.toString(2);
  for (let i = 0; i < bits.length; i += 1) {
    result = (result * result) % modulus;
    if (bits[i] === "1") {
      result = (result * normalized) % modulus;
    }
  }
  return result;
}

// ---------------------------------------------------------------------------
// PKCS#1 v1.5 填充
// ---------------------------------------------------------------------------

/**
 * 生成指定长度的非零随机字节（PKCS#1 v1.5 要求 PS 全非零）。
 *
 * @param {number} length 需要的字节数。
 * @param {Crypto} [rng] 随机源，默认全局 `crypto`。
 * @returns {Uint8Array} 非零字节数组。
 */
export function randomNonZeroBytes(length, rng = crypto) {
  if (!Number.isInteger(length) || length < 0) {
    throw new RangeError(`长度必须是非负整数，收到 ${length}`);
  }
  const out = new Uint8Array(length);
  let filled = 0;
  let rounds = 0;
  while (filled < length) {
    const batch = new Uint8Array(Math.max(32, length - filled));
    rng.getRandomValues(batch);
    for (const byte of batch) {
      if (byte !== 0x00 && filled < length) {
        out[filled] = byte;
        filled += 1;
      }
    }
    rounds += 1;
    if (rounds > 512) {
      throw new RsaError(RSA_KEY_INVALID, "随机源连续产出 0x00，PKCS#1 v1.5 填充失败");
    }
  }
  return out;
}

/**
 * 单块 PKCS#1 v1.5 加密：`EM = 00 || 02 || PS || 00 || M`。
 *
 * @param {Uint8Array} chunk 明文块（<= k-11 字节）。
 * @param {{n: bigint, e: bigint, k: number}} key 公钥参数。
 * @returns {Uint8Array} k 字节密文。
 */
function encryptBlock(chunk, key) {
  const maxChunk = key.k - 11;
  if (chunk.length > maxChunk) {
    throw new RsaError(
      RSA_KEY_INVALID,
      `明文块 ${chunk.length} 字节超过上限 ${maxChunk} 字节（k=${key.k}）`,
    );
  }
  const psLength = key.k - 3 - chunk.length;
  const block = new Uint8Array(key.k);
  block[0] = 0x00;
  block[1] = 0x02;
  block.set(randomNonZeroBytes(psLength), 2);
  block[2 + psLength] = 0x00;
  block.set(chunk, 3 + psLength);

  const message = bytesToBigInt(block);
  if (message >= key.n) {
    throw new RsaError(RSA_KEY_INVALID, "填充后的整数不小于模数 n（密钥异常）");
  }
  return bigIntToBytes(modPow(message, key.e, key.n), key.k);
}

/**
 * 单块 PKCS#1 v1.5 解密并去填充。
 *
 * @param {Uint8Array} block k 字节密文块。
 * @param {{n: bigint, d: bigint, k: number}} key 私钥参数。
 * @returns {Uint8Array} 明文块。
 * @throws {RsaError} 填充非法时抛 `RSA_DECRYPT_FAILED`。
 */
function decryptBlock(block, key) {
  if (block.length !== key.k) {
    throw new RsaError(RSA_DECRYPT_FAILED, `密文块长度 ${block.length} 字节，期望 ${key.k} 字节`);
  }
  const cipher = bytesToBigInt(block);
  if (cipher >= key.n) {
    throw new RsaError(RSA_DECRYPT_FAILED, "密文数值不小于模数 n（私钥与密文不匹配）");
  }
  const em = bigIntToBytes(modPow(cipher, key.d, key.n), key.k);
  if (em[0] !== 0x00 || em[1] !== 0x02) {
    throw new RsaError(
      RSA_DECRYPT_FAILED,
      `PKCS#1 v1.5 填充头非法（期望 00 02，实际 ${em[0].toString(16).padStart(2, "0")} ${em[1]
        .toString(16)
        .padStart(2, "0")}）`,
    );
  }
  let separator = -1;
  for (let i = 2; i < em.length; i += 1) {
    if (em[i] === 0x00) {
      separator = i;
      break;
    }
  }
  if (separator < 0) {
    throw new RsaError(RSA_DECRYPT_FAILED, "PKCS#1 v1.5 填充缺少 0x00 分隔符");
  }
  if (separator - 2 < MIN_PS_LENGTH) {
    throw new RsaError(
      RSA_DECRYPT_FAILED,
      `PKCS#1 v1.5 填充串只有 ${separator - 2} 字节，最少需要 ${MIN_PS_LENGTH} 字节`,
    );
  }
  return em.subarray(separator + 1);
}

/**
 * 把 PEM/已解析对象统一成公钥参数。
 *
 * @param {string|Uint8Array|{n: bigint, e: bigint, k: number}} key 公钥。
 * @returns {{n: bigint, e: bigint, bits: number, k: number}} 公钥参数。
 */
function resolvePublicKey(key) {
  if (key && typeof key === "object" && typeof key.n === "bigint" && typeof key.e === "bigint") {
    return key;
  }
  return parsePublicKey(key);
}

/**
 * 把 PEM/已解析对象统一成私钥参数。
 *
 * @param {string|Uint8Array|{n: bigint, d: bigint, k: number}} key 私钥。
 * @returns {{n: bigint, d: bigint, bits: number, k: number}} 私钥参数。
 */
function resolvePrivateKey(key) {
  if (key && typeof key === "object" && typeof key.n === "bigint" && typeof key.d === "bigint") {
    return key;
  }
  return parsePrivateKey(key);
}

// ---------------------------------------------------------------------------
// 分块加解密（对应 protocol.py:133-155）
// ---------------------------------------------------------------------------

/**
 * 分块 RSA 加密，返回 base64 字符串（上游 `rsa_encrypt`）。
 *
 * 1024-bit 模数下每块明文最多 117 字节、密文固定 128 字节。
 *
 * @param {Uint8Array|string} data 待加密数据。
 * @param {string|Uint8Array|object} key 公钥（PEM / DER / 已解析参数）。
 * @returns {string} base64 密文。
 * @throws {RsaError} 密钥不可解析或数据超长时。
 */
export function rsaEncryptPkcs1v15(data, key) {
  const publicKey = resolvePublicKey(key);
  const bytes = toBytes(data);
  if (bytes.length === 0) {
    throw new RsaError(RSA_KEY_INVALID, "待加密数据为空");
  }
  const maxChunk = publicKey.k - 11;
  const blockCount = Math.ceil(bytes.length / maxChunk);
  const out = new Uint8Array(blockCount * publicKey.k);
  for (let index = 0; index < blockCount; index += 1) {
    const chunk = bytes.subarray(index * maxChunk, (index + 1) * maxChunk);
    out.set(encryptBlock(chunk, publicKey), index * publicKey.k);
  }
  return bytesToBase64(out);
}

/**
 * 分块 RSA 解密，返回拼接后的明文字节（上游 `rsa_decrypt`）。
 *
 * 与上游的差异：上游遇到填充错误会静默 `break` 丢弃剩余块，这里改为抛
 * `RSA_DECRYPT_FAILED`，避免"半截 JSON"这种难以诊断的失败。
 *
 * @param {string|Uint8Array} payload base64 密文或原始字节。
 * @param {string|Uint8Array|object} key 私钥（PEM / DER / 已解析参数）。
 * @returns {Uint8Array} 明文字节。
 * @throws {RsaError} 密钥不可解析、长度非法或填充非法时。
 */
export function rsaDecryptPkcs1v15(payload, key) {
  const privateKey = resolvePrivateKey(key);
  const raw =
    typeof payload === "string" ? base64ToBytes(payload, RSA_DECRYPT_FAILED) : toBytes(payload);
  if (raw.length === 0) {
    throw new RsaError(RSA_DECRYPT_FAILED, "密文为空");
  }
  if (raw.length % privateKey.k !== 0) {
    throw new RsaError(
      RSA_DECRYPT_FAILED,
      `密文总长 ${raw.length} 字节，不是分块大小 ${privateKey.k} 的整数倍`,
    );
  }
  const blockCount = raw.length / privateKey.k;
  const parts = [];
  let total = 0;
  for (let index = 0; index < blockCount; index += 1) {
    const part = decryptBlock(raw.subarray(index * privateKey.k, (index + 1) * privateKey.k), privateKey);
    parts.push(part);
    total += part.length;
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}
