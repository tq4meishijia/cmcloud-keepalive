/**
 * 签名与时间戳测试。
 *
 * 核心是任务书 §3.3 的两组黄金向量：逐字符比对 canonical 与 40 位签名，
 * 这两组形式是服务端实测接受的形式（上游未编码形式实测被拒）。
 */

import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";

import { API_PATH, HMAC_PREFIX, SECRET_KEY } from "../src/ecloud/constants.js";
import {
  buildSignatureParams,
  buildSignedQuery,
  canonicalize,
  computeSignature,
  hmacSha1Hex,
  randomNonce,
  rfc3986Encode,
  sha256Hex,
  utc8NowText,
  utc8Timestamp,
} from "../src/ecloud/signature.js";

const GOLDEN_TIMESTAMP = "2026-01-02T03:04:05Z";

test("rfc3986Encode 等价 Python quote(safe=\"\")", () => {
  assert.equal(rfc3986Encode("+"), "%2B");
  assert.equal(rfc3986Encode("/"), "%2F");
  assert.equal(rfc3986Encode("="), "%3D");
  assert.equal(rfc3986Encode("&"), "%26");
  assert.equal(rfc3986Encode(":"), "%3A");
  assert.equal(rfc3986Encode(" "), "%20");
  assert.equal(rfc3986Encode("中文"), "%E4%B8%AD%E6%96%87");
  assert.equal(rfc3986Encode("!"), "%21");
  assert.equal(rfc3986Encode("'"), "%27");
  assert.equal(rfc3986Encode("("), "%28");
  assert.equal(rfc3986Encode(")"), "%29");
  assert.equal(rfc3986Encode("*"), "%2A");
  // unreserved 集合必须原样保留
  assert.equal(rfc3986Encode("AZaz09-_.~"), "AZaz09-_.~");
  // 上游缺陷 B 的现场：时间戳里的冒号必须变成 %3A
  assert.equal(rfc3986Encode(GOLDEN_TIMESTAMP), "2026-01-02T03%3A04%3A05Z");
  // 数字与非字符串入参
  assert.equal(rfc3986Encode(1.0), "1");
  assert.equal(rfc3986Encode(true), "true");
});

test("黄金向量 1：/user/getSysTime（无 AccessToken）", async () => {
  const params = buildSignatureParams({
    nonce: "00000000000000000000000000000001",
    timestamp: GOLDEN_TIMESTAMP,
  });
  const canonical = canonicalize(params);
  assert.equal(
    canonical,
    "AccessKey=53bb79015a3f47c4be166d9371f68f14" +
      "&SignatureMethod=HmacSHA1" +
      "&SignatureNonce=00000000000000000000000000000001" +
      "&SignatureVersion=V2.0" +
      "&Timestamp=2026-01-02T03%3A04%3A05Z",
  );

  const signature = await computeSignature("/user/getSysTime", canonical);
  assert.equal(signature, "9f76aa385a0879bebf6aa77c8b7c44fdd5f882b8");
  assert.equal(signature.length, 40);
});

test("黄金向量 1 的 stringToSign 中间值（sha256 步骤逐字节一致）", async () => {
  const canonical =
    "AccessKey=53bb79015a3f47c4be166d9371f68f14" +
    "&SignatureMethod=HmacSHA1" +
    "&SignatureNonce=00000000000000000000000000000001" +
    "&SignatureVersion=V2.0" +
    "&Timestamp=2026-01-02T03%3A04%3A05Z";
  assert.equal(
    await sha256Hex(canonical),
    "88cb7711039f523e4aaf8b2c38b389c77e2a62e680c790e331d21ef593b4b15e",
  );
  assert.equal(
    rfc3986Encode(`${API_PATH}/user/getSysTime`),
    "%2Fapi%2Fcem%2Fgateway%2Fouter%2Fcem-webapi%2Fuser%2FgetSysTime",
  );
});

test("黄金向量 2：/resource/desktopUptime（AccessToken 含 + / = & 特殊字符）", async () => {
  const params = buildSignatureParams({
    nonce: "abcdefabcdefabcdefabcdefabcdefab",
    timestamp: GOLDEN_TIMESTAMP,
    accessToken: "tok+en/with=special&chars",
  });
  const canonical = canonicalize(params);
  assert.equal(
    canonical,
    "AccessKey=53bb79015a3f47c4be166d9371f68f14" +
      "&AccessToken=tok%2Ben%2Fwith%3Dspecial%26chars" +
      "&SignatureMethod=HmacSHA1" +
      "&SignatureNonce=abcdefabcdefabcdefabcdefabcdefab" +
      "&SignatureVersion=V2.0" +
      "&Timestamp=2026-01-02T03%3A04%3A05Z",
  );

  const signature = await computeSignature("/resource/desktopUptime", canonical);
  assert.equal(signature, "6453d7f43099db00950e802bd6afe968791d4be7");
});

test("AccessToken 只在非空时出现", () => {
  const withoutToken = buildSignatureParams({ nonce: "00", timestamp: GOLDEN_TIMESTAMP });
  assert.equal("AccessToken" in withoutToken, false);

  const withToken = buildSignatureParams({
    nonce: "00",
    timestamp: GOLDEN_TIMESTAMP,
    accessToken: "abc",
  });
  assert.equal(withToken.AccessToken, "abc");
});

test("canonical 按键名升序排列", () => {
  const canonical = canonicalize({
    Timestamp: GOLDEN_TIMESTAMP,
    AccessKey: "ak",
    SignatureMethod: "HmacSHA1",
    SignatureNonce: "n",
    SignatureVersion: "V2.0",
  });
  const keys = canonical.split("&").map((pair) => pair.split("=")[0]);
  assert.deepEqual(keys, [
    "AccessKey",
    "SignatureMethod",
    "SignatureNonce",
    "SignatureVersion",
    "Timestamp",
  ]);
});

test("UTC+8 时间戳与可读时间（含跨日边界，不受本地时区影响）", () => {
  assert.equal(utc8Timestamp(new Date("2026-01-02T03:04:05Z")), "2026-01-02T11:04:05Z");
  // UTC 16:00 = 次日 00:00（UTC+8）
  assert.equal(utc8Timestamp(new Date("2026-01-01T16:00:00Z")), "2026-01-02T00:00:00Z");
  assert.equal(utc8NowText(new Date("2026-01-01T16:00:00Z")), "2026-01-02 00:00:00");
  assert.equal(utc8NowText(new Date("2026-12-31T15:59:59Z")), "2026-12-31 23:59:59");
  assert.equal(utc8Timestamp(new Date("2026-01-02T15:59:59.999Z")), "2026-01-02T23:59:59Z");
  // 非法入参必须早失败，避免把 "Invalid Date" 签进请求
  assert.throws(() => utc8Timestamp(new Date("nope")), TypeError);
  assert.throws(() => utc8NowText("2026-01-02"), TypeError);
});

test("sha256Hex / hmacSha1Hex 与 Node crypto 交叉验证", async () => {
  assert.equal(
    await sha256Hex("abc"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  const key = `${HMAC_PREFIX}${SECRET_KEY}`;
  const message = "POST\n%2Fapi\nhash";
  const expected = crypto.createHmac("sha1", key).update(message).digest("hex");
  assert.equal(await hmacSha1Hex(key, message), expected);
});

test("randomNonce 生成 32 位小写十六进制且互不相同", () => {
  const first = randomNonce();
  const second = randomNonce();
  assert.match(first, /^[0-9a-f]{32}$/);
  assert.match(second, /^[0-9a-f]{32}$/);
  assert.notEqual(first, second);
  assert.equal(randomNonce(8).length, 16);
  assert.throws(() => randomNonce(0), RangeError);
  assert.throws(() => randomNonce(1.5), RangeError);
});

test("buildSignedQuery 产出可直接拼 URL 的完整查询串", async () => {
  const signed = await buildSignedQuery({
    endpoint: "/user/getSysTime",
    now: new Date("2026-01-02T03:04:05Z"),
    nonce: "00000000000000000000000000000002",
  });
  assert.equal(signed.nonce, "00000000000000000000000000000002");
  assert.equal(signed.timestamp, "2026-01-02T11:04:05Z");
  assert.match(signed.query, /^AccessKey=[^&]+&SignatureMethod=HmacSHA1&/);
  assert.ok(signed.query.endsWith(`&Signature=${signed.signature}`));
  assert.match(signed.signature, /^[0-9a-f]{40}$/);
  // canonical 里不能残留未编码的冒号（上游缺陷 B 现场）
  assert.equal(signed.canonical.includes(":"), false);
  assert.match(signed.canonical, /Timestamp=[0-9T\-]+%3A/);
});

test("computeSignature 拒绝空 endpoint", async () => {
  await assert.rejects(() => computeSignature("", "a=b"), TypeError);
});
