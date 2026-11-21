/**
 * 内联管理面板（单文件模板字符串，无外部 CDN / 字体 / 图片）。
 *
 * 安全约束：
 *   - 所有动态文本一律用 `textContent` 写入，脚本里**没有**任何 `innerHTML` 拼接；
 *   - 页面本身不内联任何密钥，ADMIN_TOKEN 只存在使用者浏览器的 localStorage；
 *   - 后端只回显掩码后的账号与 token 尾号。
 *
 * @module dashboard
 */

import { APP_NAME, APP_VERSION } from "./ecloud/constants.js";

/**
 * HTML 转义（仅用于把项目名/版本号插进模板，动态数据一律走 textContent）。
 *
 * @param {unknown} value 待转义值。
 * @returns {string} 转义后的文本。
 */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * 渲染管理面板 HTML。
 *
 * @param {object} [options] 参数。
 * @param {string} [options.name] 项目名。
 * @param {string} [options.version] 版本号。
 * @returns {string} 完整 HTML 文档。
 */
export function renderDashboard({ name = APP_NAME, version = APP_VERSION } = {}) {
  const safeName = escapeHtml(name);
  const safeVersion = escapeHtml(version);

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>${safeName} 管理面板</title>
<style>
:root{
  --bg:#f5f6f8;--panel:#ffffff;--border:#e1e5ea;--text:#1b1f24;--muted:#5c6672;
  --accent:#0b6efd;--ok:#1a7f37;--warn:#9a6700;--err:#c62828;--code:#f0f2f5;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0e1116;--panel:#161b22;--border:#262d37;--text:#e6edf3;--muted:#96a0ad;
    --accent:#4c8dff;--ok:#3fb950;--warn:#d29922;--err:#f85149;--code:#1d232c;
  }
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg);color:var(--text);
  font:15px/1.55 system-ui,-apple-system,"Segoe UI","Noto Sans SC",sans-serif;
  -webkit-text-size-adjust:100%;
}
header.bar{
  display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:space-between;
  padding:14px 20px;background:var(--panel);border-bottom:1px solid var(--border);
}
.brand{display:flex;align-items:center;gap:10px;min-width:0}
.brand h1{font-size:17px;margin:0;font-weight:650;letter-spacing:.2px;overflow-wrap:anywhere}
.tag{font:12px/1 var(--mono);color:var(--muted);border:1px solid var(--border);border-radius:999px;padding:3px 8px}
.dot{width:10px;height:10px;border-radius:50%;display:inline-block;flex:0 0 auto;background:var(--muted)}
.dot-ok{background:var(--ok);box-shadow:0 0 0 3px color-mix(in srgb,var(--ok) 22%,transparent)}
.dot-err{background:var(--err);box-shadow:0 0 0 3px color-mix(in srgb,var(--err) 22%,transparent)}
.dot-warn{background:var(--warn)}
.token-box{display:flex;align-items:center;gap:8px}
.token-box label{font-size:12px;color:var(--muted);font-family:var(--mono)}
main{max-width:1080px;margin:0 auto;padding:20px;display:grid;gap:16px}
.cards{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))}
.card,.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px}
.card h2,.panel h2{margin:0 0 12px;font-size:13px;font-weight:650;color:var(--muted);text-transform:uppercase;letter-spacing:.6px}
dl{margin:0;display:grid;grid-template-columns:auto 1fr;gap:6px 12px;font-size:14px}
dt{color:var(--muted);white-space:nowrap}
dd{margin:0;overflow-wrap:anywhere;font-family:var(--mono);font-size:13px}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px}
.row:last-child{margin-bottom:0}
label{font-size:13px;color:var(--muted)}
input,select,button{font:inherit;color:var(--text)}
input,select{
  background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:7px 10px;min-width:0;flex:1 1 160px;
}
button{
  background:var(--accent);color:#fff;border:1px solid transparent;border-radius:8px;
  padding:8px 14px;cursor:pointer;font-weight:600;
}
button:hover{filter:brightness(1.06)}
button:disabled{opacity:.55;cursor:not-allowed}
button.ghost{background:transparent;color:var(--text);border-color:var(--border)}
button.danger{color:var(--err);border-color:color-mix(in srgb,var(--err) 45%,var(--border))}
.message{margin:4px 0 0;font-size:13px;min-height:20px;overflow-wrap:anywhere}
.message.ok{color:var(--ok)}
.message.warn{color:var(--warn)}
.message.err{color:var(--err)}
.checks{list-style:none;margin:0;padding:0;display:grid;gap:8px}
.checks li{display:grid;grid-template-columns:18px 1fr;gap:8px;font-size:13px;align-items:start}
.checks .mark{font-weight:700;font-family:var(--mono)}
.checks .mark.ok{color:var(--ok)}
.checks .mark.err{color:var(--err)}
.checks .detail{color:var(--muted);overflow-wrap:anywhere}
.logs{list-style:none;margin:0;padding:0;display:grid;gap:4px;font-family:var(--mono);font-size:12.5px;max-height:340px;overflow:auto}
.logs li{display:grid;grid-template-columns:132px 52px 1fr;gap:8px;padding:4px 0;border-bottom:1px dashed var(--border);overflow-wrap:anywhere}
.logs .t{color:var(--muted)}
.logs .lv{font-weight:700}
.logs .lv.error{color:var(--err)}
.logs .lv.warn{color:var(--warn)}
.logs .lv.info{color:var(--ok)}
.hidden{display:none}
footer{padding:0 20px 28px;max-width:1080px;margin:0 auto;font-size:12px;color:var(--muted)}
@media (max-width:720px){
  .cards{grid-template-columns:1fr}
  .logs li{grid-template-columns:1fr;gap:2px}
  header.bar{align-items:flex-start}
  .token-box{width:100%}
}
</style>
</head>
<body>
<header class="bar">
  <div class="brand">
    <span id="health-dot" class="dot dot-warn" title="正在检查部署健康状态"></span>
    <h1>${safeName}</h1>
    <span class="tag">v${safeVersion}</span>
  </div>
  <div class="token-box">
    <label for="admin-token">ADMIN_TOKEN</label>
    <input id="admin-token" type="password" autocomplete="off" spellcheck="false" placeholder="未配置则留空">
    <button id="save-token" class="ghost" type="button">保存</button>
  </div>
</header>

<main>
  <section class="cards">
    <article class="card">
      <h2>凭证</h2>
      <dl id="card-credentials"></dl>
    </article>
    <article class="card">
      <h2>选中桌面</h2>
      <dl id="card-selected"></dl>
    </article>
    <article class="card">
      <h2>最近保活</h2>
      <dl id="card-lastrun"></dl>
    </article>
  </section>

  <section class="panel">
    <h2>操作</h2>
    <div class="row">
      <button id="btn-keepalive" type="button">立即保活</button>
      <button id="btn-refresh" class="ghost" type="button">刷新列表</button>
      <button id="btn-diagnose" class="ghost" type="button">自检</button>
      <button id="btn-logout" class="ghost danger" type="button">退出登录</button>
    </div>
    <div class="row">
      <label for="machine-select">桌面</label>
      <select id="machine-select"></select>
      <button id="btn-select" class="ghost" type="button">选定</button>
    </div>
    <form id="login-form" class="row">
      <label for="login-username">账号</label>
      <input id="login-username" autocomplete="username" spellcheck="false">
      <label for="login-password">密码</label>
      <input id="login-password" type="password" autocomplete="current-password">
      <button type="submit">登录</button>
    </form>
    <p id="message" class="message" role="status" aria-live="polite"></p>
  </section>

  <section id="warnings-box" class="panel hidden">
    <h2>配置告警</h2>
    <ul id="warnings" class="checks"></ul>
  </section>

  <section id="checks-box" class="panel hidden">
    <h2>自检结果</h2>
    <ul id="checks" class="checks"></ul>
  </section>

  <section class="panel">
    <h2>最近日志（20 条）</h2>
    <ol id="logs" class="logs"></ol>
  </section>
</main>

<footer>仅供学习研究使用，请遵守云服务条款。接口需要 ADMIN_TOKEN 时请先在上方填写。</footer>

<script>
(function () {
  'use strict';

  var TOKEN_KEY = 'cmcloud-keepalive:admin-token';

  function el(id) { return document.getElementById(id); }

  function getToken() {
    try { return window.localStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; }
  }

  function setToken(value) {
    try {
      if (value) { window.localStorage.setItem(TOKEN_KEY, value); }
      else { window.localStorage.removeItem(TOKEN_KEY); }
    } catch (e) { /* 隐私模式下 localStorage 可能不可用，忽略即可 */ }
  }

  function setMessage(text, kind) {
    var node = el('message');
    node.textContent = text || '';
    node.className = 'message' + (kind ? ' ' + kind : '');
  }

  function setRows(id, rows) {
    var dl = el(id);
    while (dl.firstChild) { dl.removeChild(dl.firstChild); }
    for (var i = 0; i < rows.length; i += 1) {
      var dt = document.createElement('dt');
      dt.textContent = rows[i][0];
      var dd = document.createElement('dd');
      dd.textContent = rows[i][1] === null || rows[i][1] === undefined || rows[i][1] === ''
        ? '—'
        : String(rows[i][1]);
      dl.appendChild(dt);
      dl.appendChild(dd);
    }
  }

  function callApi(path, options) {
    var opts = options || {};
    var headers = {};
    if (opts.body) { headers['Content-Type'] = 'application/json'; }
    var token = getToken();
    if (token) { headers['Authorization'] = 'Bearer ' + token; }

    var init = { method: opts.method || 'GET', headers: headers };
    if (opts.body) { init.body = JSON.stringify(opts.body); }

    return fetch(path, init).then(function (response) {
      return response.text().then(function (text) {
        var data = null;
        if (text) {
          try { data = JSON.parse(text); }
          catch (e) { data = { ok: false, error: '响应不是合法 JSON：' + text.slice(0, 120) }; }
        }
        if (data === null) { data = { ok: false, error: '空响应（HTTP ' + response.status + '）' }; }
        data.status = response.status;
        return data;
      });
    }, function (error) {
      throw new Error('网络错误：' + (error && error.message ? error.message : String(error)));
    });
  }

  function applyWarnings(warnings) {
    var box = el('warnings-box');
    var list = el('warnings');
    while (list.firstChild) { list.removeChild(list.firstChild); }
    if (!warnings || warnings.length === 0) { box.className = 'panel hidden'; return; }
    for (var i = 0; i < warnings.length; i += 1) {
      var li = document.createElement('li');
      var mark = document.createElement('span');
      mark.className = 'mark err';
      mark.textContent = '!';
      var detail = document.createElement('span');
      detail.className = 'detail';
      detail.textContent = warnings[i];
      li.appendChild(mark);
      li.appendChild(detail);
      list.appendChild(li);
    }
    box.className = 'panel';
  }

  function renderMachines(machines, selected) {
    var select = el('machine-select');
    var items = (machines && machines.items) || [];
    while (select.firstChild) { select.removeChild(select.firstChild); }
    if (items.length === 0) {
      var empty = document.createElement('option');
      empty.value = '';
      empty.textContent = '（暂无桌面，请先登录并刷新）';
      select.appendChild(empty);
      return;
    }
    var selectedId = selected && selected.instanceId ? selected.instanceId : '';
    for (var i = 0; i < items.length; i += 1) {
      var option = document.createElement('option');
      option.value = items[i].instanceId;
      var label = items[i].machineName || items[i].instanceId;
      if (items[i].status !== null && items[i].status !== undefined) {
        label += '（' + items[i].status + '）';
      }
      option.textContent = label;
      if (items[i].instanceId === selectedId) { option.selected = true; }
      select.appendChild(option);
    }
  }

  function renderLogs(logs) {
    var list = el('logs');
    while (list.firstChild) { list.removeChild(list.firstChild); }
    var entries = (logs || []).slice(-20).reverse();
    if (entries.length === 0) {
      var empty = document.createElement('li');
      var span = document.createElement('span');
      span.className = 't';
      span.textContent = '暂无日志';
      empty.appendChild(span);
      list.appendChild(empty);
      return;
    }
    for (var i = 0; i < entries.length; i += 1) {
      var entry = entries[i];
      var li = document.createElement('li');
      var time = document.createElement('span');
      time.className = 't';
      time.textContent = entry.ts || '';
      var level = document.createElement('span');
      level.className = 'lv ' + (entry.level || 'info');
      level.textContent = entry.level || 'info';
      var message = document.createElement('span');
      message.textContent = entry.msg || '';
      li.appendChild(time);
      li.appendChild(level);
      li.appendChild(message);
      list.appendChild(li);
    }
  }

  function renderChecks(checks) {
    var box = el('checks-box');
    var list = el('checks');
    while (list.firstChild) { list.removeChild(list.firstChild); }
    if (!checks || checks.length === 0) { box.className = 'panel hidden'; return; }
    for (var i = 0; i < checks.length; i += 1) {
      var li = document.createElement('li');
      var mark = document.createElement('span');
      mark.className = 'mark ' + (checks[i].ok ? 'ok' : 'err');
      mark.textContent = checks[i].ok ? 'OK' : 'NG';
      var detail = document.createElement('span');
      detail.className = 'detail';
      detail.textContent = (checks[i].name || 'check') + '：' + (checks[i].detail || '');
      li.appendChild(mark);
      li.appendChild(detail);
      list.appendChild(li);
    }
    box.className = 'panel';
  }

  function renderStatus(data) {
    var configured = data.configured || {};
    var credentials = data.credentials;
    var selected = data.selected;
    var lastRun = data.lastRun;

    setRows('card-credentials', [
      ['账号', credentials ? credentials.username : '未登录'],
      ['保存时间', credentials ? credentials.savedAt : null],
      ['Token 尾号', credentials ? credentials.tokenTail : null],
      ['环境变量账号', configured.username || '未配置'],
      ['存储', data.storage === 'kv' ? 'KEEPALIVE_KV' : '进程内存（仅调试）'],
      ['鉴权', configured.authDisabled ? '未启用（无 ADMIN_TOKEN）' : '已启用']
    ]);

    setRows('card-selected', [
      ['桌面名', selected ? selected.machineName : null],
      ['instanceId', selected ? selected.instanceId : null],
      ['machineId', selected ? selected.machineId : null],
      ['公钥', configured.publicKey ? '可解析' : '不可解析'],
      ['私钥', configured.privateKey ? '已配置' : '未配置（响应保持加密）']
    ]);

    setRows('card-lastrun', [
      ['时间', lastRun ? lastRun.ts : null],
      ['结果', lastRun ? (lastRun.ok ? '成功' : '失败') : null],
      ['运行时长', lastRun ? lastRun.uptimeText : null],
      ['connect 码', lastRun ? lastRun.connectStatus : null],
      ['token 过期', lastRun ? (lastRun.tokenExpired ? '是' : '否') : null],
      ['错误', lastRun ? lastRun.error : null]
    ]);

    renderMachines(data.machines, selected);
    renderLogs(data.logs);
    applyWarnings(data.warnings);
  }

  function refreshStatus() {
    return callApi('/api/status').then(function (data) {
      if (!data.ok) {
        setMessage('读取状态失败：' + (data.error || ('HTTP ' + data.status)), 'err');
        return data;
      }
      renderStatus(data);
      return data;
    });
  }

  function checkHealth() {
    var dot = el('health-dot');
    return callApi('/api/health').then(function (data) {
      if (data && data.ok) {
        dot.className = 'dot dot-ok';
        dot.title = '部署健康（服务器时间 ' + (data.time || '未知') + '）';
      } else {
        dot.className = 'dot dot-err';
        dot.title = '健康检查失败：' + (data && data.error ? data.error : '未知原因');
      }
      return data;
    }, function (error) {
      dot.className = 'dot dot-err';
      dot.title = '健康检查不可达：' + error.message;
      throw error;
    });
  }

  function summarize(action, data) {
    if (action === 'keepalive') {
      return data.ok
        ? '保活成功：' + (data.uptimeText || '运行时长未知') + '（connect=' + data.connectStatus + '）'
        : '保活失败：' + (data.error || '未提供原因');
    }
    if (action === 'refresh') {
      var count = data.machines ? data.machines.length : 0;
      return data.ok ? '已刷新 ' + count + ' 个桌面' : '刷新失败：' + (data.error || '未提供原因');
    }
    if (action === 'login') {
      if (!data.ok) { return '登录失败：' + (data.hint || data.error || '未提供原因'); }
      var machines = data.machines ? data.machines.length : 0;
      var extra = data.warning ? '（' + data.warning + '）' : '';
      return '登录成功：' + (data.username || '') + '，共 ' + machines + ' 个桌面' + extra;
    }
    if (action === 'select') {
      return data.ok
        ? '已选定：' + (data.selected && data.selected.machineName ? data.selected.machineName : '')
        : '选定失败：' + (data.error || '未提供原因');
    }
    if (action === 'logout') {
      return data.ok ? '本地凭证已清除' : '退出失败：' + (data.error || '未提供原因');
    }
    if (action === 'diagnose') {
      renderChecks(data.checks);
      if (!data.ok) {
        var failed = (data.checks || []).filter(function (check) { return !check.ok; });
        return '自检未全通过（' + failed.length + ' 项失败）：' + (failed[0] ? failed[0].name : '');
      }
      return '自检全部通过';
    }
    return '完成';
  }

  function runAction(action, label, task) {
    setMessage(label + ' 执行中…', 'warn');
    return task().then(function (data) {
      var ok = Boolean(data && data.ok);
      setMessage(summarize(action, data), ok ? 'ok' : 'err');
      return data;
    }).catch(function (error) {
      setMessage(label + ' 失败：' + error.message, 'err');
      return null;
    }).then(function (data) {
      return refreshStatus().then(function () { return data; }, function () { return data; });
    });
  }

  function bind() {
    el('admin-token').value = getToken();

    el('save-token').addEventListener('click', function () {
      setToken(el('admin-token').value.trim());
      setMessage('Token 已保存到本机 localStorage', 'ok');
      refreshStatus().catch(function (error) { setMessage('读取状态失败：' + error.message, 'err'); });
    });

    el('btn-keepalive').addEventListener('click', function () {
      runAction('keepalive', '保活', function () {
        return callApi('/api/keepalive', { method: 'POST', body: {} });
      });
    });

    el('btn-refresh').addEventListener('click', function () {
      runAction('refresh', '刷新列表', function () {
        return callApi('/api/refresh', { method: 'POST', body: {} });
      });
    });

    el('btn-diagnose').addEventListener('click', function () {
      runAction('diagnose', '自检', function () {
        return callApi('/api/diagnose', { method: 'POST', body: {} });
      });
    });

    el('btn-logout').addEventListener('click', function () {
      runAction('logout', '退出登录', function () {
        return callApi('/api/logout', { method: 'POST', body: {} });
      });
    });

    el('btn-select').addEventListener('click', function () {
      var instanceId = el('machine-select').value;
      if (!instanceId) { setMessage('请先选择桌面', 'err'); return; }
      runAction('select', '选定桌面', function () {
        return callApi('/api/select', { method: 'POST', body: { instanceId: instanceId } });
      });
    });

    el('login-form').addEventListener('submit', function (event) {
      event.preventDefault();
      var username = el('login-username').value.trim();
      var password = el('login-password').value;
      if (!username || !password) { setMessage('账号与密码都不能为空', 'err'); return; }
      runAction('login', '登录', function () {
        return callApi('/api/login', { method: 'POST', body: { username: username, password: password } });
      }).then(function () {
        el('login-password').value = '';
      });
    });
  }

  bind();
  checkHealth().catch(function () { /* 已在 checkHealth 内标注状态点 */ });
  refreshStatus().catch(function (error) { setMessage('读取状态失败：' + error.message, 'err'); });
  window.setInterval(function () {
    checkHealth().catch(function () { /* 忽略轮询失败 */ });
  }, 60000);
}());
</script>
</body>
</html>`;
}
