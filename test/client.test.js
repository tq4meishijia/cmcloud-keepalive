/**
 * `EcloudClient` 测试：注入假 fetch，完全不访问真实网络。
 *
 * 覆盖点：
 *   - 请求体经 RSA 加密后能解回，业务字段/公共字段/accessToken 的合并顺序与上游一致
 *   - URL 上带 canonical + Signature，`AccessToken` 只在有 token 时出现
 *   - 加密响应能解出 `body`；无私钥时返回 `{_encrypted:true}`
 *   - 非 2xx、非法 JSON、公钥不可解析都有可诊断错误
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { loadConfig } from "../src/config.js";
import { describeSignatureFailure } from "../src/api.js";
import { EcloudClient, EcloudError } from "../src/ecloud/client.js";
import { API_PATH, BASE_URL } from "../src/ecloud/constants.js";
import { rsaDecryptPkcs1v15, rsaEncryptPkcs1v15 } from "../src/ecloud/rsa.js";

const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 1024 });
const PUBLIC_PEM = publicKey.export({ type: "spki", format: "pem" });
const PRIVATE_PEM = privateKey.export({ type: "pkcs8", format: "pem" });

const UTC8_NOW = () => new Date("2026-01-02T03:04:05Z");
const CONFIG = loadConfig({
  ECLOUD_RSA_PUBLIC_KEY: PUBLIC_PEM,
  ECLOUD_RSA_PRIVATE_KEY: PRIVATE_PEM,
});

/**
 * 造一个假 fetch：解密请求体、记录现场、返回可控响应。
 *
 * @param {object} [options] 选项。
 * @param {unknown} [options.response] 以 JSON 返回的响应体。
 * @param {number} [options.status] HTTP 状态码。
 * @param {string} [options.rawText] 直接指定的响应文本（优先于 response）。
 * @returns {{fetchImpl: Function, captured: object}} 假 fetch 与捕获现场。
 */
function createHarness({ response = {}, status = 200, rawText } = {}) {
  const captured = { urls: [], requests: [], headers: [], bodies: [] };
  const fetchImpl = async (url, init) => {
    captured.urls.push(url);
    captured.headers.push(init.headers);
    const body = JSON.parse(init.body);
    captured.bodies.push(body);
    const plain = rsaDecryptPkcs1v15(body.params, PRIVATE_PEM);
    captured.requests.push(JSON.parse(Buffer.from(plain).toString("utf8")));
    const text = rawText === undefined ? JSON.stringify(response) : rawText;
    return new Response(text, { status, headers: { "Content-Type": "application/json" } });
  };
  return { fetchImpl, captured };
}

/**
 * URL 的查询串部分。
 *
 * @param {string} url 完整 URL。
 * @returns {string} 查询串。
 */
function queryOf(url) {
  const index = url.indexOf("?");
  return index < 0 ? "" : url.slice(index + 1);
}

test("请求体字段合并顺序与上游一致（业务 → 公共 → accessToken）", async () => {
  const { fetchImpl, captured } = createHarness({ response: { body: { uptimeSeconds: 1 } } });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "device-uid-1",
    accessToken: "token-abc",
    fetchImpl,
    now: UTC8_NOW,
  });

  await client.desktopUptime("instance-1");

  assert.equal(captured.requests.length, 1);
  const sent = captured.requests[0];
  assert.deepEqual(Object.keys(sent), [
    "instanceId",
    "companyCode",
    "version",
    "clientVersion",
    "deviceUid",
    "accessToken",
  ]);
  assert.equal(sent.instanceId, "instance-1");
  assert.equal(sent.companyCode, "ECloud");
  assert.equal(sent.version, "1.0.0");
  assert.equal(sent.clientVersion, "3.8.2");
  assert.equal(sent.deviceUid, "device-uid-1");
  assert.equal(sent.accessToken, "token-abc");
});

test("URL 命中正确端点并携带 canonical + Signature", async () => {
  const { fetchImpl, captured } = createHarness({ response: { body: {} } });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "device-uid-1",
    accessToken: "token-abc",
    fetchImpl,
    now: UTC8_NOW,
  });

  await client.desktopUptime("instance-1");

  const url = captured.urls[0];
  assert.ok(url.startsWith(`${BASE_URL}${API_PATH}/resource/desktopUptime?`), url);
  const query = queryOf(url);
  assert.match(query, /(^|&)Signature=[0-9a-f]{40}$/);
  assert.match(query, /AccessKey=53bb79015a3f47c4be166d9371f68f14/);
  assert.match(query, /SignatureMethod=HmacSHA1/);
  assert.match(query, /SignatureVersion=V2\.0/);
  assert.match(query, /AccessToken=token-abc/);
  // canonical 已做 RFC3986 编码：查询串里不应出现裸冒号
  assert.equal(query.includes(":"), false);
  assert.match(query, /Timestamp=2026-01-02T11%3A04%3A05Z/);
});

test("无 accessToken 时 URL 不出现 AccessToken 参数", async () => {
  const { fetchImpl, captured } = createHarness({ response: { ok: 1 } });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "device-uid-1",
    accessToken: "",
    fetchImpl,
    now: UTC8_NOW,
  });

  await client.getSysTime();

  assert.equal(queryOf(captured.urls[0]).includes("AccessToken"), false);
  assert.equal(captured.requests[0].accessToken, "");
  assert.deepEqual(Object.keys(captured.requests[0]), [
    "companyCode",
    "version",
    "clientVersion",
    "deviceUid",
    "accessToken",
  ]);
});

test("请求头与上游一致", async () => {
  const { fetchImpl, captured } = createHarness({ response: {} });
  const client = new EcloudClient({ config: CONFIG, deviceUid: "d", fetchImpl, now: UTC8_NOW });
  await client.getSysTime();
  assert.equal(captured.headers[0]["User-Agent"], "Ecloud-CloudPC/3.8.2");
  assert.equal(captured.headers[0]["Content-Type"], "application/json;charset=UTF-8");
});

test("fetchImpl 不依赖调用点的 this（workerd Illegal invocation 回归）", async () => {
  const seen = [];

  // 关键：用普通 function 而不是箭头函数，并模拟 workerd 对 this 的严格要求。
  // workerd 的全局 fetch 是 WebIDL 全局操作，this 必须是全局作用域，
  // 否则抛 `Illegal invocation: function called with incorrect this reference`。
  // 之前把全局 fetch 存成实例属性再以 this.fetchImpl(...) 调用，就会踩这个坑。
  function workerdLikeFetch(url, init) {
    if (this !== globalThis) {
      throw new TypeError(
        "Illegal invocation: function called with incorrect `this` reference",
      );
    }
    seen.push({ url, method: init.method });
    return Promise.resolve(new Response(JSON.stringify({ body: "ok" }), { status: 200 }));
  }

  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl: workerdLikeFetch,
    now: UTC8_NOW,
  });

  const result = await client.getSysTime();

  assert.deepEqual(result, { body: "ok" }, "fetch 抛错会被包装成 EcloudError，此处必须拿到正常响应");
  assert.equal(seen.length, 1);
  assert.match(seen[0].url, /\/user\/getSysTime\?/, "请求真的发出去了");
  assert.equal(seen[0].method, "POST");
});

test("fetchImpl 不是函数时早期失败", () => {
  assert.throws(
    () => new EcloudClient({ config: CONFIG, fetchImpl: null }),
    (error) => error instanceof EcloudError && /fetchImpl/.test(error.message),
  );
});

test("加密响应能被私钥解出 body", async () => {
  const plaintext = JSON.stringify({ body: { uptimeSeconds: 42 }, errorCode: 0 });
  const encrypted = rsaEncryptPkcs1v15(Buffer.from(plaintext, "utf8"), PUBLIC_PEM);
  const { fetchImpl } = createHarness({ response: { params: encrypted } });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl,
    now: UTC8_NOW,
  });

  const result = await client.desktopUptime("instance-1");
  assert.deepEqual(result, { body: { uptimeSeconds: 42 }, errorCode: 0 });
});

test("未配置私钥时返回 {_encrypted:true, params}", async () => {
  const encrypted = rsaEncryptPkcs1v15(Buffer.from(JSON.stringify({ body: "x" }), "utf8"), PUBLIC_PEM);
  const { fetchImpl } = createHarness({ response: { params: encrypted } });
  const noPrivateKeyConfig = loadConfig({ ECLOUD_RSA_PUBLIC_KEY: PUBLIC_PEM });
  const client = new EcloudClient({
    config: noPrivateKeyConfig,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl,
    now: UTC8_NOW,
  });

  const result = await client.getSysTime();
  assert.equal(result._encrypted, true);
  assert.equal(result.params, encrypted);
});

test("非 2xx 抛出带 status 与响应体片段的错误", async () => {
  const { fetchImpl } = createHarness({
    status: 400,
    rawText: JSON.stringify({
      errorCode: "INVALID_PARAMETER",
      errorMessage: "Invalid parameter Signature ",
    }),
  });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl,
    now: UTC8_NOW,
  });

  await assert.rejects(
    () => client.getSysTime(),
    (error) => {
      assert.ok(error instanceof EcloudError);
      assert.equal(error.status, 400);
      assert.match(error.body, /INVALID_PARAMETER/);
      assert.match(error.message, /HTTP 400/);
      return true;
    },
  );
});

test("响应不是 JSON 时给出可诊断错误", async () => {
  const { fetchImpl } = createHarness({ rawText: "<html>502 Bad Gateway</html>" });
  const client = new EcloudClient({ config: CONFIG, deviceUid: "d", fetchImpl, now: UTC8_NOW });
  await assert.rejects(
    () => client.getSysTime(),
    (error) => error instanceof EcloudError && /不是合法 JSON/.test(error.message),
  );
});

test("公钥是上游占位符时拒绝发请求，并指向 ECLOUD_RSA_PUBLIC_KEY", async () => {
  let called = false;
  const fetchImpl = async () => {
    called = true;
    return new Response("{}", { status: 200 });
  };
  const client = new EcloudClient({
    config: loadConfig({}),
    deviceUid: "d",
    fetchImpl,
    now: UTC8_NOW,
  });

  await assert.rejects(
    () => client.getSysTime(),
    (error) =>
      error instanceof EcloudError &&
      error.code === "RSA_KEY_INVALID" &&
      /ECLOUD_RSA_PUBLIC_KEY/.test(error.message) &&
      /占位符/.test(error.message),
  );
  assert.equal(called, false, "公钥不可解析时不应发出任何请求");
});

test("私钥不可解析时解密失败并指出 ECLOUD_RSA_PRIVATE_KEY", async () => {
  const encrypted = rsaEncryptPkcs1v15(Buffer.from(JSON.stringify({ body: "x" }), "utf8"), PUBLIC_PEM);
  const { fetchImpl } = createHarness({ response: { params: encrypted } });
  const badPrivateConfig = loadConfig({
    ECLOUD_RSA_PUBLIC_KEY: PUBLIC_PEM,
    ECLOUD_RSA_PRIVATE_KEY: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----",
  });
  const client = new EcloudClient({
    config: badPrivateConfig,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl,
    now: UTC8_NOW,
  });

  await assert.rejects(
    () => client.getSysTime(),
    (error) => /ECLOUD_RSA_PRIVATE_KEY/.test(error.message),
  );
});

test("getDeviceInfo 取 body.machineList，缺失时返回空数组", async () => {
  const harnessWithList = createHarness({
    response: { body: { machineList: [{ instanceId: "i-1", machineId: "m-1" }] } },
  });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl: harnessWithList.fetchImpl,
    now: UTC8_NOW,
  });
  const machines = await client.getDeviceInfo();
  assert.equal(machines.length, 1);
  assert.equal(machines[0].instanceId, "i-1");

  const sent = harnessWithList.captured.requests[0];
  assert.equal(sent.allCompany, true);
  assert.equal(sent.accessToken, "t");
  assert.equal(sent.companyCode, "ECloud");
  assert.equal(sent.version, "1.0.0");

  const harnessWithoutList = createHarness({ response: { body: {} } });
  const client2 = new EcloudClient({
    config: CONFIG,
    deviceUid: "d",
    accessToken: "t",
    fetchImpl: harnessWithoutList.fetchImpl,
    now: UTC8_NOW,
  });
  assert.deepEqual(await client2.getDeviceInfo(), []);
});

test("loginWithPassword 的 timestamp 使用注入时钟且带 clientNeedTwoFactor", async () => {
  const { fetchImpl, captured } = createHarness({ response: { body: { accessTicket: "tk" } } });
  const client = new EcloudClient({ config: CONFIG, deviceUid: "d", fetchImpl, now: UTC8_NOW });
  const result = await client.loginWithPassword("user", "secret");

  assert.equal(result.body.accessTicket, "tk");
  const sent = captured.requests[0];
  assert.equal(sent.username, "user");
  assert.equal(sent.password, "secret");
  assert.equal(sent.timestamp, "2026-01-02T11:04:05Z");
  assert.equal(sent.clientNeedTwoFactor, true);
});

test("verifyAccessTicket 把票据放在 accessTicket 字段", async () => {
  const { fetchImpl, captured } = createHarness({ response: { body: { accessToken: "at" } } });
  const client = new EcloudClient({ config: CONFIG, deviceUid: "d", fetchImpl, now: UTC8_NOW });
  const result = await client.verifyAccessTicket("ticket-1");
  assert.equal(result.body.accessToken, "at");
  assert.equal(captured.requests[0].accessTicket, "ticket-1");
});

test("注入固定 nonce 时 URL 可复现", async () => {
  const { fetchImpl, captured } = createHarness({ response: {} });
  const client = new EcloudClient({
    config: CONFIG,
    deviceUid: "d",
    fetchImpl,
    now: UTC8_NOW,
    nonce: "00000000000000000000000000000003",
  });
  await client.getSysTime();
  assert.match(queryOf(captured.urls[0]), /SignatureNonce=00000000000000000000000000000003/);
});

test("endpoint 必须以 / 开头", async () => {
  const client = new EcloudClient({ config: CONFIG, deviceUid: "d", fetchImpl: async () => new Response("{}") });
  await assert.rejects(() => client.post("user/getSysTime"), EcloudError);
});

test("describeSignatureFailure 三态判读：500 表示签名已过、公钥不配对", () => {
  const serverErrorBody = '{"status":500,"error":"Internal Server Error"}';

  // ① 实测形态：合法但与服务端不配对的 1024-bit 公钥 → HTTP 500
  //    这是"公钥配错"最典型的表现，绝不能落进"网关不可达/网关挂了"的文案。
  const http500 = new EcloudError(`HTTP 500 /user/getSysTime：${serverErrorBody}`, {
    status: 500,
    body: serverErrorBody,
  });
  const text500 = describeSignatureFailure(http500);
  assert.match(text500, /签名已通过/, "必须点明签名已通过，否则会被误读成签名实现有问题");
  assert.match(text500, /不配对/, "必须指向公钥与服务端私钥不配对");
  assert.match(text500, /HTTP 500/);
  assert.match(text500, /Internal Server Error/, "必须保留原文片段便于排查");
  assert.doesNotMatch(text500, /网关不可达/);

  // ② 签名真有问题：400 INVALID_PARAMETER
  const http400 = new EcloudError("HTTP 400 /user/getSysTime：{\"errorCode\":\"INVALID_PARAMETER\"}", {
    status: 400,
    body: '{"errorCode":"INVALID_PARAMETER","errorMessage":"Invalid parameter Signature "}',
  });
  assert.match(describeSignatureFailure(http400), /签名被拒绝/);

  // ③ 真的到不了网关（网络层异常）
  const networkError = new EcloudError("请求 /user/getSysTime 失败：getaddrinfo ENOTFOUND cloudpc.ecloud.10086.cn");
  assert.match(describeSignatureFailure(networkError), /网关不可达/);
});
