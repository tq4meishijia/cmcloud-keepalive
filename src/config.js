/**
 * 配置装载：`env` → 不可变 config 对象。
 *
 * 设计要点：
 *   - **不抛异常**。密钥不可解析时把结论写进 `publicKeyValid / publicKeyError`，
 *     让 `/api/status`、`/api/diagnose`、面板都能报出可读原因；真正需要密钥时
 *     由 `EcloudClient` 抛 `RSA_KEY_INVALID`（不能静默失败）。
 *   - **绝不回显密钥**。config 只在内存里，`/api/status` 只暴露布尔与掩码。
 *   - 所有字段都有默认值，未配置任何变量也能启动（只是不能保活）。
 *
 * @module config
 */

import {
  APP_NAME,
  APP_VERSION,
  CLIENT_VERSION,
  COMPANY_CODE,
  UPSTREAM_RSA_PUBLIC_KEY_PEM,
} from "./ecloud/constants.js";
import { validatePrivateKey, validatePublicKey } from "./ecloud/rsa.js";

/** `rsaPublicKey` 来自环境变量的标记。 */
export const PUBLIC_KEY_SOURCE_ENV = "env";

/** `rsaPublicKey` 来自上游占位符的标记。 */
export const PUBLIC_KEY_SOURCE_PLACEHOLDER = "upstream-placeholder";

/**
 * 读取字符串型环境变量。
 *
 * @param {Record<string, unknown>} env Workers env。
 * @param {string} name 变量名。
 * @param {string} [fallback] 缺省值。
 * @returns {string} 去空白后的字符串；未配置或只含空白时返回 fallback。
 */
function readString(env, name, fallback = "") {
  const raw = env?.[name];
  if (raw === undefined || raw === null) return fallback;
  const text = String(raw).trim();
  return text === "" ? fallback : text;
}

/**
 * 读取 PEM 型环境变量。
 *
 * 兼容把多行 PEM 塞进单一字符串（字面量 `\n`）的写法；`wrangler secret put` 支持真换行，
 * 但 `wrangler.toml` 的 `[vars]` 不支持，这里统一兜住。
 *
 * @param {Record<string, unknown>} env Workers env。
 * @param {string} name 变量名。
 * @param {string} [fallback] 缺省值。
 * @returns {string} PEM 文本。
 */
function readPem(env, name, fallback = "") {
  const text = readString(env, name, fallback);
  if (text === "") return "";
  if (!text.includes("\n") && text.includes("\\n")) {
    return text.replace(/\\n/g, "\n");
  }
  return text;
}

/**
 * 读取布尔型环境变量，仅 `"false"`（忽略大小写）视为 false。
 *
 * @param {Record<string, unknown>} env Workers env。
 * @param {string} name 变量名。
 * @param {boolean} fallback 缺省值。
 * @returns {boolean} 布尔值。
 */
function readBool(env, name, fallback) {
  const raw = env?.[name];
  if (raw === undefined || raw === null || String(raw).trim() === "") return fallback;
  return String(raw).trim().toLowerCase() !== "false";
}

/**
 * 把 env 冻结成配置对象。
 *
 * @param {Record<string, unknown>} [env] Workers 的 env 绑定对象。
 * @returns {Readonly<{
 *   name: string, version: string, clientVersion: string, companyCode: string,
 *   username: string, password: string,
 *   rsaPublicKey: string, rsaPrivateKey: string,
 *   publicKeySource: string, publicKeyValid: boolean, publicKeyBits: number|null, publicKeyError: string|null,
 *   privateKeyConfigured: boolean, privateKeyValid: boolean, privateKeyBits: number|null, privateKeyError: string|null,
 *   instanceId: string, adminToken: string, autoRelogin: boolean, warnings: readonly string[]
 * }>} 不可变配置对象。
 */
export function loadConfig(env = {}) {
  const envPublicKey = readPem(env, "ECLOUD_RSA_PUBLIC_KEY");
  const rsaPublicKey = envPublicKey || UPSTREAM_RSA_PUBLIC_KEY_PEM;
  const publicKeySource = envPublicKey ? PUBLIC_KEY_SOURCE_ENV : PUBLIC_KEY_SOURCE_PLACEHOLDER;

  const rsaPrivateKey = readPem(env, "ECLOUD_RSA_PRIVATE_KEY");
  const publicKeyCheck = validatePublicKey(rsaPublicKey);
  const privateKeyCheck = rsaPrivateKey
    ? validatePrivateKey(rsaPrivateKey)
    : { ok: false, bits: null, error: null };

  const adminToken = readString(env, "ADMIN_TOKEN");
  const username = readString(env, "ECLOUD_USERNAME");
  const password = readString(env, "ECLOUD_PASSWORD");

  /** @type {string[]} */
  const warnings = [];
  if (!publicKeyCheck.ok) {
    warnings.push(
      `ECLOUD_RSA_PUBLIC_KEY 不可解析（来源：${publicKeySource}）：${publicKeyCheck.error}。` +
        "所有加密请求都会失败，请用 `npx wrangler secret put ECLOUD_RSA_PUBLIC_KEY` 配置真实公钥。",
    );
  }
  if (rsaPrivateKey && !privateKeyCheck.ok) {
    warnings.push(
      `ECLOUD_RSA_PRIVATE_KEY 不可解析：${privateKeyCheck.error}。响应解密会失败，建议删除该密钥或修正内容。`,
    );
  }
  if (adminToken === "") {
    warnings.push("未配置 ADMIN_TOKEN：/api/* 无鉴权，任何能访问该 Worker 的人都能操作。");
  }
  if (username === "" || password === "") {
    warnings.push("未同时配置 ECLOUD_USERNAME / ECLOUD_PASSWORD：token 过期后无法自动重登，需手动 POST /api/login。");
  }

  return Object.freeze({
    name: APP_NAME,
    version: APP_VERSION,
    clientVersion: CLIENT_VERSION,
    companyCode: COMPANY_CODE,

    username,
    password,

    rsaPublicKey,
    rsaPrivateKey,
    publicKeySource,
    publicKeyValid: publicKeyCheck.ok,
    publicKeyBits: publicKeyCheck.bits,
    publicKeyError: publicKeyCheck.error,

    privateKeyConfigured: rsaPrivateKey !== "",
    privateKeyValid: privateKeyCheck.ok,
    privateKeyBits: privateKeyCheck.bits,
    privateKeyError: privateKeyCheck.error,

    instanceId: readString(env, "ECLOUD_INSTANCE_ID"),
    adminToken,
    autoRelogin: readBool(env, "AUTO_RELOGIN", true),
    warnings: Object.freeze(warnings),
  });
}
