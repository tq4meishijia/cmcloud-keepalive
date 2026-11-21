/**
 * Worker 入口：`fetch` 路由 + `scheduled`（Cron Trigger）。
 *
 * 路由：
 *   GET  /              → 内联管理面板 HTML
 *   *    /api/*         → `src/api.js`（JSON in/out）
 *   其他                → 404 JSON
 *
 * 与上游的对应关系：
 *   `python main.py login`                        → `POST /api/login`
 *   `python main.py desktop-keepalive --rounds 1` → `POST /api/keepalive`
 *   `python main.py desktop-keepalive --loop`     → Cron Trigger（默认每 5 分钟，见 wrangler.toml）
 *
 * @module index
 */

import { handleApiRequest } from "./api.js";
import { loadConfig } from "./config.js";
import { renderDashboard } from "./dashboard.js";
import { utc8NowText } from "./ecloud/signature.js";
import { describeError, runKeepaliveRound } from "./keepalive.js";
import { createStore } from "./store.js";

const JSON_HEADERS = Object.freeze({
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
});

const HTML_HEADERS = Object.freeze({
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
});

/**
 * 构造 JSON 响应。
 *
 * @param {unknown} data 响应体。
 * @param {number} [status] 状态码。
 * @returns {Response} 响应。
 */
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

export default {
  /**
   * HTTP 入口。
   *
   * @param {Request} request 请求。
   * @param {Record<string, unknown>} [env] Workers env 绑定。
   * @returns {Promise<Response>} 响应（任何异常都转成 500 JSON，不向平台抛错）。
   */
  async fetch(request, env = {}) {
    const now = () => new Date();
    try {
      const url = new URL(request.url);
      const path = url.pathname;
      const method = String(request.method ?? "GET").toUpperCase();
      const { state } = createStore(env, { now });

      if (path === "/" || path === "/index.html") {
        if (method !== "GET") {
          return jsonResponse({ ok: false, error: `方法不允许：${method} ${path}` }, 405);
        }
        const config = loadConfig(env);
        return new Response(renderDashboard({ name: config.name, version: config.version }), {
          status: 200,
          headers: HTML_HEADERS,
        });
      }

      if (path.startsWith("/api/")) {
        return await handleApiRequest({ request, env, state, now });
      }

      return jsonResponse(
        { ok: false, error: `未知路径：${path}（管理面板在 /，接口在 /api/*）` },
        404,
      );
    } catch (error) {
      return jsonResponse({ ok: false, error: `内部错误：${describeError(error)}` }, 500);
    }
  },

  /**
   * Cron 入口。
   *
   * 关键约束：**不能让异常冒泡到平台**（Cron 抛错会污染 Workers 指标并触发告警），
   * 因此这里三层兜底：`runKeepaliveRound` 内部不抛错 → 本函数 try/catch 落地日志
   * → `waitUntil` 上再挂一次 `.catch`。
   *
   * @param {{cron?: string, scheduledTime?: number}} controller Cron 控制器。
   * @param {Record<string, unknown>} [env] Workers env 绑定。
   * @param {{waitUntil?: (promise: Promise<unknown>) => void}} [ctx] 执行上下文。
   * @returns {Promise<void>} 完成。
   */
  async scheduled(controller, env = {}, ctx) {
    const now = () => new Date();
    const cron = controller?.cron ?? "unknown";
    let state;
    try {
      state = createStore(env, { now }).state;
    } catch (error) {
      console.error(`[keepalive] cron ${cron} 初始化存储失败：${describeError(error)}`);
      return;
    }

    const task = (async () => {
      try {
        await state.appendLog("info", `cron 触发：${cron}`);
      } catch (error) {
        console.warn(`[keepalive] 写入 cron 日志失败：${describeError(error)}`);
      }
      try {
        const result = await runKeepaliveRound({ env, state, now });
        console.log(
          `[keepalive] cron ${cron} 完成：ok=${result.ok} uptime=${
            result.uptimeText ?? "未知"
          } connect=${result.connectStatus}`,
        );
        return result;
      } catch (error) {
        const message = `[cron] 保活轮次异常：${describeError(error)}`;
        console.error(message);
        try {
          await state.appendLog("error", message);
          await state.setLastRun({
            ts: utc8NowText(now()),
            ok: false,
            uptimeSeconds: null,
            uptimeText: null,
            connectStatus: "unknown",
            tokenExpired: false,
            error: message,
          });
        } catch (nested) {
          console.error(`[keepalive] 记录异常失败：${describeError(nested)}`);
        }
        return null;
      }
    })();

    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(
        task.catch((error) => {
          console.error(`[keepalive] scheduled 兜底异常：${describeError(error)}`);
        }),
      );
      return;
    }
    await task;
  },
};
