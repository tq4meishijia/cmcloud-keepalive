/**
 * 移动云电脑（Ecloud CloudPC）协议常量。
 *
 * 逐项对齐上游 `legacy/python/protocol.py:35-52`（逆向 V3.8.2 客户端所得）。
 * 这些值来自公开客户端二进制的协议逆向，不含任何用户账号或用户密钥，
 * 但真实可用的 RSA 公钥**不在**本文件内（见 UPSTREAM_RSA_PUBLIC_KEY_PEM 注释）。
 *
 * @module ecloud/constants
 */

/** 网关域名。 */
export const BASE_URL = "https://cloudpc.ecloud.10086.cn";

/** 统一路由前缀，所有端点都拼在其后。 */
export const API_PATH = "/api/cem/gateway/outer/cem-webapi";

/** 签名用 AccessKey（客户端内置、非用户凭证）。 */
export const ACCESS_KEY = "53bb79015a3f47c4be166d9371f68f14";

/** HmacSHA1 签名密钥（客户端内置、非用户凭证）。 */
export const SECRET_KEY = "6b0d3b93f3aa4c7ea076c841bead1ddd";

/** 签名密钥的固定盐前缀。 */
export const HMAC_PREFIX = "BC_SIGNATURE&";

/** 业务参数 companyCode。 */
export const COMPANY_CODE = "ECloud";

/** 伪装客户端版本号。 */
export const CLIENT_VERSION = "3.8.2";

/** settingValue 密钥派生用的平台标识。 */
export const PLATFORM = "win32";

/** 请求体版本号（commonParams.version）。 */
export const REQUEST_VERSION = "1.0.0";

/** HTTP User-Agent，与上游一致。 */
export const USER_AGENT = `Ecloud-CloudPC/${CLIENT_VERSION}`;

/** 单次 HTTP 请求超时（毫秒）。 */
export const REQUEST_TIMEOUT_MS = 30000;

/** 1024-bit 模数对应的 RSA 明文分块大小：128 - 11 = 117 字节。 */
export const RSA_CHUNK_IN = 117;

/** 1024-bit 模数对应的 RSA 密文分块大小：128 字节。 */
export const RSA_CHUNK_OUT = 128;

/** Worker 名称（用于 /api/health 与面板标题）。 */
export const APP_NAME = "cmcloud-keepalive";

/** 移植实现版本号。 */
export const APP_VERSION = "1.0.0";

/**
 * 上游仓库内置的 RSA 公钥 —— **这是一个占位符，不可解析**。
 *
 * 复核结论（见 `docs/ANALYSIS.md` §9 缺陷 A）：base64 解码后 DER 为 282 字节，
 * 而 1024-bit SPKI 公钥应为 162 字节；外层 SEQUENCE 只声明到第 162 字节
 * （`30 81 9f` + 159 字节内容），与实际 282 字节不符，OpenSSL / 任意 DER 解析器都会失败。
 * 上游作者在发布前把真实公钥替换掉了，模数区还残留 `nLkGj8xJBH5iH5R3JXqK7lJn` 的重复填充串。
 *
 * 因此本移植**不会**用它发请求，只作为"未配置密钥"的可诊断默认值：
 * 运行时真正的公钥从 `env.ECLOUD_RSA_PUBLIC_KEY` 读取；
 * 若仍取到本占位符，`validatePublicKey()` 返回 `{ ok:false }`，
 * `/api/diagnose` 会明确报出"当前公钥不可解析（疑似上游占位符）"。
 *
 * 原值按字节保留，便于对照上游与做回归测试。
 */
export const UPSTREAM_RSA_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC3Oa6pJGpNMnzJSXl2LgXtfBcP
nLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJn
GxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJ
BH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKf
JnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3
JXqK7lJnGxJh5lKfJnLgXtbHnLkGj8xJBH5iH5R3JXqK7lJnGwIDAQAB
-----END PUBLIC KEY-----`;
