/**
 * Ecloud CloudPC 协议 HTTP 客户端（对应上游 `protocol.py:217-355` 的 `EcloudHTTP`）。
 *
 * 职责边界刻意收窄：只负责「签 URL + 加密 body + 发请求 + 解响应」，
 * 不读写任何持久化状态（上游把 `data/*.json` 硬编码进构造函数，是移植时必须解耦的地方）。
 * 状态由 `src/store.js` 注入。
 *
 * @module ecloud/client
 */

import {
  API_PATH,
  BASE_URL,
  CLIENT_VERSION,
  COMPANY_CODE,
  REQUEST_TIMEOUT_MS,
  REQUEST_VERSION,
  USER_AGENT,
} from "./constants.js";
import {
  RSA_DECRYPT_FAILED,
  RSA_KEY_INVALID,
  RsaError,
  parsePrivateKey,
  parsePublicKey,
  rsaDecryptPkcs1v15,
  rsaEncryptPkcs1v15,
} from "./rsa.js";
import { buildSignedQuery, utc8Timestamp } from "./signature.js";

/** 通用请求失败错误码。 */
export const ECLOUD_REQUEST_FAILED = "ECLOUD_REQUEST_FAILED";

const UTF8_ENCODER = new TextEncoder();
const UTF8_DECODER = new TextDecoder();

/**
 * 把任意异常转成可读文本。
 *
 * @param {unknown} error 异常。
 * @returns {string} 文本。
 */
function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

/** Ecloud 协议层错误，上层可通过 `code` / `status` / `body` 分支处理。 */
export class EcloudError extends Error {
  /**
   * @param {string} message 可诊断的中文错误信息。
   * @param {object} [options] 附加信息。
   * @param {string} [options.code] 错误码，默认 `ECLOUD_REQUEST_FAILED`。
   * @param {number|null} [options.status] HTTP 状态码。
   * @param {string} [options.body] 响应体（截断后），便于排查。
   * @param {unknown} [options.cause] 原始异常。
   */
  constructor(message, { code = ECLOUD_REQUEST_FAILED, status = null, body = "", cause } = {}) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "EcloudError";
    this.code = code;
    this.status = status;
    this.body = body;
  }
}

/**
 * 归一化 fetch 实现：固定绑定到 `globalThis` 后再存进实例。
 *
 * **为什么必须 bind**：workerd 的全局 `fetch` 是 WebIDL 全局操作，要求调用时
 * `this` 指向全局作用域。若把它存成对象属性再以 `this.fetchImpl(url, init)` 调用，
 * `this` 就变成该对象，workerd 直接抛
 *
 *   Illegal invocation: function called with incorrect `this` reference
 *
 * 而 Node 的 `fetch` 对此完全宽松、测试里注入的假 fetch 又是箭头函数（不关心 `this`），
 * 所以这个坑**只在真实部署时暴露**，单测全绿也发现不了。这里统一 bind 之后，
 * 调用点用 `this.fetchImpl(...)` 还是裸调用都安全。
 *
 * @param {unknown} fetchImpl fetch 实现。
 * @returns {typeof fetch} 已绑定全局作用域的 fetch。
 * @throws {EcloudError} 传入的不是函数时。
 */
function resolveFetch(fetchImpl) {
  if (typeof fetchImpl !== "function") {
    throw new EcloudError("fetchImpl 必须是函数（默认使用全局 fetch）");
  }
  return fetchImpl.bind(globalThis);
}

/**
 * 移动云电脑协议客户端。
 *
 * 所有副作用都可通过构造参数注入：`fetchImpl`（网络）、`now`（时钟）、`nonce`（签名随机数），
 * 因此测试不需要真实网络。
 *
 * @example
 * const client = new EcloudClient({ config, deviceUid, accessToken });
 * const uptime = await client.desktopUptime("instance-xxx");
 */
export class EcloudClient {
  /**
   * @param {object} options 构造参数。
   * @param {object} options.config `loadConfig(env)` 产出的配置对象（读取 rsaPublicKey / rsaPrivateKey）。
   * @param {string} [options.deviceUid] 设备指纹 deviceUid，写入每个请求的 commonParams。
   * @param {string} [options.accessToken] 访问令牌，空串表示未登录（登录类端点仍可用）。
   * @param {typeof fetch} [options.fetchImpl] fetch 实现；内部会 bind 到 `globalThis` 以规避 workerd 的 Illegal invocation。
   * @param {() => Date} [options.now] 时钟。
   * @param {string|null} [options.nonce] 固定 nonce（仅测试用）。
   * @throws {EcloudError} 缺少 config 或 fetchImpl 不是函数时。
   */
  constructor({
    config,
    deviceUid = "",
    accessToken = "",
    fetchImpl = fetch,
    now = () => new Date(),
    nonce = null,
  } = {}) {
    if (!config || typeof config !== "object") {
      throw new EcloudError("EcloudClient 需要 config：请先调用 loadConfig(env)");
    }
    this.config = config;
    this.deviceUid = deviceUid;
    this.accessToken = accessToken;
    this.fetchImpl = resolveFetch(fetchImpl);
    this.now = now;
    this.nonce = nonce;
    /** @type {object|null} 惰性解析缓存，避免每次请求重复解析 PEM。 */
    this._publicKey = null;
    this._privateKey = null;
  }

  /**
   * 取公钥参数（惰性解析 + 缓存）。
   *
   * @returns {object} 公钥参数。
   * @throws {EcloudError} 公钥不可解析时，错误信息直接指向 ECLOUD_RSA_PUBLIC_KEY。
   */
  getPublicKey() {
    if (this._publicKey === null) {
      try {
        this._publicKey = parsePublicKey(this.config.rsaPublicKey);
      } catch (error) {
        throw new EcloudError(
          `无法加密请求体：ECLOUD_RSA_PUBLIC_KEY 不可用（${errorMessage(error)}）。` +
            "请用 `npx wrangler secret put ECLOUD_RSA_PUBLIC_KEY` 配置真实的 1024-bit 公钥 PEM；" +
            "仓库内置的上游值是占位符，无法解析。",
          { code: RSA_KEY_INVALID, cause: error },
        );
      }
    }
    return this._publicKey;
  }

  /**
   * 取私钥参数（惰性解析 + 缓存）。
   *
   * @returns {object} 私钥参数。
   * @throws {EcloudError} 私钥不可解析时。
   */
  getPrivateKey() {
    if (this._privateKey === null) {
      try {
        this._privateKey = parsePrivateKey(this.config.rsaPrivateKey);
      } catch (error) {
        throw new EcloudError(
          `无法解密响应：ECLOUD_RSA_PRIVATE_KEY 不可解析（${errorMessage(error)}）`,
          { code: RSA_KEY_INVALID, cause: error },
        );
      }
    }
    return this._privateKey;
  }

  /**
   * 发送一次协议级请求。
   *
   * 步骤与上游 `protocol.py:236-278` 一一对应：
   *   1. 合并业务参数 + commonParams + accessToken（后写覆盖先写）
   *   2. JSON 序列化 → RSA PKCS#1 v1.5 分块加密 → base64
   *   3. 计算签名并把 `&Signature=` 拼到 URL
   *   4. POST，超时 30s
   *   5. 响应含 `params` 且有私钥 → 解密后返回；无私钥 → 返回 `{_encrypted:true, params}`
   *
   * @param {string} endpoint 业务端点，必须以 `/` 开头。
   * @param {Record<string, unknown>} [businessParams] 业务参数。
   * @returns {Promise<Record<string, unknown>>} 解析（并视配置解密）后的响应对象。
   * @throws {EcloudError} 网络失败、非 2xx、响应非法 JSON、密钥不可用时。
   */
  async post(endpoint, businessParams = {}) {
    if (typeof endpoint !== "string" || !endpoint.startsWith("/")) {
      throw new EcloudError(`endpoint 必须以 "/" 开头，收到 "${endpoint}"`);
    }

    // 1. 合并参数：业务参数在前，公共参数居中，accessToken 最后（与 protocol.py:254 一致）。
    const commonParams = {
      companyCode: COMPANY_CODE,
      version: REQUEST_VERSION,
      clientVersion: this.config.clientVersion || CLIENT_VERSION,
      deviceUid: this.deviceUid,
    };
    const merged = { ...businessParams, ...commonParams, accessToken: this.accessToken };

    // 2. 请求体加密。
    let paramsBase64;
    try {
      paramsBase64 = rsaEncryptPkcs1v15(UTF8_ENCODER.encode(JSON.stringify(merged)), this.getPublicKey());
    } catch (error) {
      if (error instanceof EcloudError) throw error;
      throw new EcloudError(`请求体加密失败（${endpoint}）：${errorMessage(error)}`, {
        code: RSA_KEY_INVALID,
        cause: error,
      });
    }

    // 3. 签名。
    const signed = await buildSignedQuery({
      endpoint,
      now: this.now(),
      accessToken: this.accessToken,
      nonce: this.nonce || undefined,
    });
    const url = `${BASE_URL}${API_PATH}${endpoint}?${signed.query}`;

    // 4. 发送。`this.fetchImpl` 在构造时已 bind(globalThis)，因此这里即使以方法形式
    //    调用也不会触发 workerd 的 "Illegal invocation"（见 resolveFetch 注释）。
    let response;
    try {
      response = await this.fetchImpl(url, {
        method: "POST",
        headers: {
          "User-Agent": USER_AGENT,
          "Content-Type": "application/json;charset=UTF-8",
        },
        body: JSON.stringify({ params: paramsBase64 }),
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch (error) {
      throw new EcloudError(`请求 ${endpoint} 失败：${errorMessage(error)}`, { cause: error });
    }

    const text = await response.text();
    if (!response.ok) {
      throw new EcloudError(
        `HTTP ${response.status} ${endpoint}：${text.slice(0, 500) || "（空响应体）"}`,
        { status: response.status, body: text },
      );
    }

    let parsed;
    try {
      parsed = text === "" ? {} : JSON.parse(text);
    } catch (error) {
      throw new EcloudError(`响应不是合法 JSON（${endpoint}）：${text.slice(0, 200)}`, {
        body: text,
        cause: error,
      });
    }

    // 5. 解密。
    return this._unwrapResponse(endpoint, parsed);
  }

  /**
   * 处理加密响应。
   *
   * @param {string} endpoint 端点（用于错误信息）。
   * @param {Record<string, unknown>} parsed 原始响应对象。
   * @returns {Record<string, unknown>} 明文响应，或 `{_encrypted:true, params}`。
   * @throws {EcloudError} 解密失败时。
   */
  _unwrapResponse(endpoint, parsed) {
    const isEnvelope =
      parsed !== null && typeof parsed === "object" && typeof parsed.params === "string";
    if (!isEnvelope) return parsed;

    if (!this.config.rsaPrivateKey) {
      // 上游缺陷 C：无私钥时解密分支是死代码。这里保留密文并显式标注，由上层给出可读状态。
      return { _encrypted: true, params: parsed.params };
    }

    let plain;
    try {
      plain = rsaDecryptPkcs1v15(parsed.params, this.getPrivateKey());
    } catch (error) {
      if (error instanceof EcloudError) throw error;
      throw new EcloudError(`响应解密失败（${endpoint}）：${errorMessage(error)}`, {
        code: error instanceof RsaError ? error.code : RSA_DECRYPT_FAILED,
        cause: error,
      });
    }

    const text = UTF8_DECODER.decode(plain);
    try {
      return JSON.parse(text);
    } catch (error) {
      throw new EcloudError(`解密后的响应不是合法 JSON（${endpoint}）：${text.slice(0, 200)}`, {
        code: RSA_DECRYPT_FAILED,
        body: text,
        cause: error,
      });
    }
  }

  /**
   * 获取服务器时间（验证签名是否被服务端接受）。
   *
   * @returns {Promise<Record<string, unknown>>} 响应体。
   */
  async getSysTime() {
    return this.post("/user/getSysTime", {});
  }

  /**
   * 密码登录，换 `accessTicket`。
   *
   * @param {string} username 账号。
   * @param {string} password 密码。
   * @returns {Promise<Record<string, unknown>>} 含 `body.accessTicket` 或 `errorCode`。
   */
  async loginWithPassword(username, password) {
    return this.post("/login/verify", {
      username,
      password,
      timestamp: utc8Timestamp(this.now()),
      clientNeedTwoFactor: true,
    });
  }

  /**
   * 用 `accessTicket` 换 `accessToken`。
   *
   * @param {string} accessTicket 登录返回的临时票据。
   * @returns {Promise<Record<string, unknown>>} 含 `body.accessToken`。
   */
  async verifyAccessTicket(accessTicket) {
    return this.post("/login/verifyAccessTicket", { accessTicket });
  }

  /**
   * 拉取桌面列表。
   *
   * @returns {Promise<Array<Record<string, unknown>>>} `body.machineList`，缺失时返回空数组。
   */
  async getDeviceInfo() {
    const result = await this.post("/user/getDeviceInfo", {
      accessToken: this.accessToken,
      companyCode: COMPANY_CODE,
      allCompany: true,
      version: REQUEST_VERSION,
    });
    const list = result?.body?.machineList;
    return Array.isArray(list) ? list : [];
  }

  /**
   * 查询桌面累计在线时长（保活核心接口）。
   *
   * @param {string} instanceId 桌面实例 ID。
   * @returns {Promise<Record<string, unknown>>} 响应体（被加密且无私钥时为 `{_encrypted:true}`）。
   */
  async desktopUptime(instanceId) {
    return this.post("/resource/desktopUptime", { instanceId });
  }

  /**
   * 会话登记（保活辅助接口），等价官方客户端点"连接"时的那一发请求。
   *
   * @param {string} instanceId 桌面实例 ID。
   * @param {string} [machineId] 机器 ID。
   * @returns {Promise<Record<string, unknown>>} 含 `errorCode`。
   */
  async machineConnect(instanceId, machineId = "") {
    return this.post("/session/machineConnect", { instanceId, machineId });
  }
}
