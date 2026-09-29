// 路由级测试：自建内存 KV，验证首次初始化、鉴权、管理 API 的行为。
// 跑: node test/route.test.mjs
import assert from "node:assert/strict";
import worker from "../src/index.js";
import { warpUsable } from "../src/warp.js";
import { mintToken } from "../src/auth.js";

const PW = "test-password-123";

// 内存版 KV：get 支持 "json" 模式，与 CF KV 语义对齐
class MemKV {
  constructor() { this.store = new Map(); }
  async get(k, type) {
    const v = this.store.get(k);
    if (v == null) return null;
    return type === "json" ? JSON.parse(v) : v;
  }
  async put(k, v) { this.store.set(k, v); }
  async delete(k) { this.store.delete(k); }
}

let kv, env;
function freshEnv() {
  kv = new MemKV();
  env = { KV: kv };
  return env;
}

const call = (path, opt = {}) =>
  worker.fetch(new Request(`https://x.dev${path}`, {
    headers: { "cf-connecting-ip": "9.9.9.9", ...(opt.headers || {}) },
    method: opt.method || "GET",
    body: opt.body,
  }), env);

const send = (path, payload, headers) =>
  call(path, { method: "POST", body: JSON.stringify(payload), headers });

// 预置一台 WARP 设备：重建走 KV 缓存，不联网注册
const FAKE_WARP = JSON.stringify({
  deviceId: "dev-1", privateKey: "PRIV", peerPublicKey: "PUB",
  ipv4: "172.16.0.2", ipv6: "2606:4700::100::1",
  registeredAt: new Date().toISOString(),
});

let pass = 0, fail = 0;
const test = async (name, fn) => {
  try {
    await fn();
    pass++;
    console.log("  ✓", name);
  } catch (e) {
    fail++;
    console.log("  ✗", name, "-", e.message);
  }
};

// ---- 环境自检 ----
await test("KV 未绑给出绑定指引", async () =>
  assert.match(await (await call("/")).text(), /KV 未绑定/));

// ---- 首次初始化 ----
freshEnv();
await test("未初始化时 / 落 404（初始化走 /api/setup）", async () =>
  assert.equal((await call("/")).status, 404));
await test("未初始化时其他路径同样 404", async () =>
  assert.equal((await call("/api/refresh")).status, 404));
await test("过短口令被挡", async () =>
  assert.equal((await send("/api/setup", { password: "short", confirm: "short" })).status, 400));
await test("两次输入对不上被挡", async () =>
  assert.equal((await send("/api/setup",
    { password: "longenough-12", confirm: "totally-different" })).status, 400));

const setup = await send("/api/setup", { password: PW, confirm: PW });
const setCookie = setup.headers.get("set-cookie") || "";
await test("初始化返回 200", () => assert.equal(setup.status, 200));
await test("会话 cookie 名为 om_session", () => assert.ok(setCookie.includes("om_session=")));
await test("cookie 标记 HttpOnly", () => assert.ok(setCookie.includes("HttpOnly")));
await test("cookie 标记 Secure", () => assert.ok(setCookie.includes("Secure")));
await test("cookie 标记 SameSite", () => assert.ok(setCookie.includes("SameSite")));
await test("cookie 里没有口令原文", () => assert.ok(!setCookie.includes(PW)));
await test("KV 存档里没有口令原文", () =>
  assert.ok(!JSON.stringify([...kv.store.values()]).includes(PW)));
// 已初始化后 /api/setup 走未登录分支返回 404 —— 不泄露"已初始化"这个事实
await test("初始化完成后 /api/setup 关闭", async () =>
  assert.equal((await send("/api/setup", { password: "another123", confirm: "another123" })).status, 404));

// 真正的竞态：两个请求同时读到 cred 为空（独立环境，不碰外层 kv/env）
{
  const solo = new MemKV();
  const e2 = { KV: solo };
  const relay = (path, payload) => worker.fetch(new Request(`https://x.dev${path}`, {
    method: "POST", headers: { "cf-connecting-ip": "9.9.9.9" },
    body: JSON.stringify(payload),
  }), e2);
  const [a, b] = await Promise.all([
    relay("/api/setup", { password: "racer-aaaa-11", confirm: "racer-aaaa-11" }),
    relay("/api/setup", { password: "racer-bbbb-22", confirm: "racer-bbbb-22" }),
  ]);
  const codes = [a.status, b.status].sort();
  await test(`并发初始化只成一个 (${codes.join("/")})`, () => {
    assert.equal(codes[0], 200);
    assert.equal(codes[1], 409);
  });
}

const session = { cookie: setCookie.split(";")[0] };

// ---- 初始化后的门禁（页面与登录接口均已砍，一律 404 不 401）----
await test("带 cookie 访问 / 仍 404", async () =>
  assert.equal((await call("/", { headers: session })).status, 404));
await test("匿名访问 / 404", async () => assert.equal((await call("/")).status, 404));
await test("匿名访问管理接口 404", async () =>
  assert.equal((await call("/api/refresh")).status, 404));

// ---- 订阅 ----
kv.store.set("config:yaml", "# fake\nproxies: []");
kv.store.set("warp:device", FAKE_WARP);
// 订阅与管理接口共用同一套 token，直接从存档签出
const tok = await mintToken(JSON.parse(kv.store.get("auth:cred")));
await test("能签出会话 token", () => assert.ok(tok));

const sub = await call(`/sub?token=${tok}`);
await test("默认地址 /sub 凭 token 可取", () => assert.equal(sub.status, 200));
await test("正文类型是 yaml", () =>
  assert.match(sub.headers.get("content-type") || "", /yaml/));
await test("带 4 小时更新间隔头", () =>
  assert.equal(sub.headers.get("profile-update-interval"), "4"));
// 文件名不能带引号：部分客户端不解析，会把 "x" 当成文件名显示出来
await test("文件名不包引号", () =>
  assert.equal(sub.headers.get("content-disposition"),
    "attachment; filename=opera-masque.yaml"));
await test("不带 token 也能取（永久地址）", async () =>
  assert.equal((await call("/sub")).status, 200));
await test("错 token 取订阅 404", async () =>
  assert.equal((await call("/sub?token=bad.sig")).status, 404));
await test("订阅 cache-control = no-cache（可走 304 协商）", () =>
  assert.equal(sub.headers.get("cache-control"), "no-cache"));
await test("响应带 nosniff 安全头", () =>
  assert.equal(sub.headers.get("x-content-type-options"), "nosniff"));
await test("响应带 Referrer-Policy: no-referrer", () =>
  assert.equal(sub.headers.get("referrer-policy"), "no-referrer"));

// ---- 订阅地址更换 ----
await test("夹带斜杠的地址被挡", async () =>
  assert.equal((await send("/api/sub-path", { path: "a/b" }, session)).status, 400));
await test("撞保留字的地址被挡", async () =>
  assert.equal((await send("/api/sub-path", { path: "api" }, session)).status, 400));
await test("正常地址更换成功", async () =>
  assert.equal((await send("/api/sub-path", { path: "my-secret" }, session)).status, 200));
await test("订阅挪到新地址", async () =>
  assert.equal((await call(`/my-secret?token=${tok}`)).status, 200));
await test("旧地址随即失效", async () =>
  assert.equal((await call(`/sub?token=${tok}`)).status, 404));

// ---- 口令更换 ----
const NEW_PW = "brandnew-123";
await test("当前口令不对拒绝更换", async () =>
  assert.equal((await send("/api/password",
    { current: "wrong", password: NEW_PW, confirm: NEW_PW }, session)).status, 401));
await test("新口令过短拒绝", async () =>
  assert.equal((await send("/api/password",
    { current: PW, password: "x1", confirm: "x1" }, session)).status, 400));

const changed = await send("/api/password",
  { current: PW, password: NEW_PW, confirm: NEW_PW }, session);
await test("口令更换成功", () => assert.equal(changed.status, 200));
await test("换完重新下发会话 cookie", () =>
  assert.ok((changed.headers.get("set-cookie") || "").includes("om_session=")));
await test("换口令后旧订阅 token 作废", async () =>
  assert.equal((await call(`/my-secret?token=${tok}`)).status, 404));

// ---- 按需重建：没过期用缓存，过期才重建 ----
{
  freshEnv();
  await send("/api/setup", { password: PW, confirm: PW });
  const tk = await mintToken(JSON.parse(kv.store.get("auth:cred")));
  kv.store.set("warp:device", FAKE_WARP);

  // 一份还没过期的配置：访问订阅不该触发重建
  kv.store.set("config:yaml", "# cached\nproxies: []");
  kv.store.set("state:meta", JSON.stringify({
    updatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3 * 3600 * 1000).toISOString(),
    stats: {}, warp: {},
  }));
  const hit = await call(`/sub?token=${tk}`);
  await test("未到期直接回缓存", async () =>
    assert.match(await hit.text(), /# cached/));

  // 已过期 + 别人握着锁：用旧配置顶住。这里不真联网，靠锁占位验证分支
  kv.store.set("state:meta", JSON.stringify({
    updatedAt: new Date(Date.now() - 5 * 3600 * 1000).toISOString(),
    expiresAt: new Date(Date.now() - 3600 * 1000).toISOString(),
    stats: {}, warp: {},
  }));
  kv.store.set("rebuild:lock", String(Date.now()));
  const busy = await call(`/sub?token=${tk}`);
  await test("过期但他人重建中仍回旧配置", async () =>
    assert.match(await busy.text(), /# cached/));

  // 过期 + 无缓存 + 抢不到锁：只能 503
  kv.store.delete("rebuild:lock");
  kv.store.delete("config:yaml");
  kv.store.set("state:meta", JSON.stringify({ expiresAt: new Date(Date.now() - 1).toISOString() }));
  kv.store.set("rebuild:lock", String(Date.now()));
  const starved = await call(`/sub?token=${tk}`);
  await test("既过期又无存底时回 503", () => assert.equal(starved.status, 503));
}

// ---- 流水线触发重建：top100:nodes → stats ----
{
  freshEnv();
  await send("/api/setup", { password: PW, confirm: PW });
  kv.store.set("warp:device", FAKE_WARP);
  // 推送令牌键名沿用历史 proton:token（生成路由已砍，由流水线直接写 KV）
  const PTK = "pipeline-token-0123456789abcdef";
  kv.store.set("proton:token", PTK);
  // 2 个可转换的节点 + 1 个缺 server 的坏节点（geo 供节点名"地区-IP"）
  kv.store.set("top100:nodes", JSON.stringify([
    { proto: "vless", server: "1.2.3.4", port: 443, ident: "uuid-1", geo: "JP" },
    { proto: "vless", server: "5.6.7.8", port: 8443, ident: "uuid-2", geo: "US" },
    { proto: "vless", server: "", port: 443, ident: "uuid-3" },
  ]));
  const push = (p) => worker.fetch(new Request(`https://x.dev${p}`, {
    method: "POST", headers: { "cf-connecting-ip": "9.9.9.9" }, body: "{}",
  }), env);

  const resp = await push(`/push/${PTK}/rebuild`);
  const body = await resp.json();
  await test("rebuild 推送被接受", () => {
    assert.equal(resp.status, 200);
    assert.equal(body.ok, true);
  });
  await test("stats 带 warpEndpoints / top100 计数", () =>
    assert.ok(body.stats && typeof body.stats.warpEndpoints === "number" &&
      typeof body.stats.top100 === "number"));
  await test("top100 计数 = 转换成功的节点数", () => assert.equal(body.stats.top100, 2));
  const meta = JSON.parse(kv.store.get("state:meta"));
  await test("top100Raw 记录读入总数 3、成功 2", () => {
    assert.equal(meta.stats.top100Raw, 3);
    assert.equal(meta.stats.top100, 2);
  });
  await test("重建出的正文含 top100 节点（名=地区-IP）", () =>
    assert.ok((kv.store.get("config:yaml") || "").includes('name: "JP-1.2.3.4"')));

  // /push/<令牌> 只留 rebuild 分支
  await test("非 rebuild 的子路径 404", async () =>
    assert.equal((await push(`/push/${PTK}/wind`)).status, 404));
  await test("不带子路径的老格式仍触发重建", async () =>
    assert.equal((await push(`/push/${PTK}`)).status, 200));
  await test("令牌不对 404", async () =>
    assert.equal((await push("/push/wrongtoken/rebuild")).status, 404));
}

// ---- 304 协商链（审计 G1 盲区）----
{
  freshEnv();
  await send("/api/setup", { password: PW, confirm: PW });
  kv.store.set("warp:device", FAKE_WARP);
  kv.store.set("config:yaml", "# etag-base\nproxies: []");
  kv.store.set("state:meta", JSON.stringify({
    updatedAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 3600_000).toISOString(),
    stats: {}, warp: {},
  }));
  const first = await call("/sub");
  const tag = first.headers.get("etag");
  await test("订阅 200 且带 128 位 hex ETag", () => {
    assert.equal(first.status, 200);
    assert.match(tag || "", /^"[0-9a-f]{32}"$/);
  });
  const hit = await call("/sub", { headers: { "if-none-match": tag } });
  await test("同值 If-None-Match → 304 空正文", async () => {
    assert.equal(hit.status, 304);
    assert.equal(await hit.text(), "");
  });
  await test("304 仍回带同值 ETag 与安全头", () => {
    assert.equal(hit.headers.get("etag"), tag);
    assert.equal(hit.headers.get("x-content-type-options"), "nosniff");
  });
  const weak = await call("/sub", { headers: { "if-none-match": `W/${tag}` } });
  await test("弱前缀 W/ 命中 304", () => assert.equal(weak.status, 304));
  const listed = await call("/sub", { headers: { "if-none-match": `"other", ${tag}` } });
  await test("逗号列表含同值命中 304", () => assert.equal(listed.status, 304));
  const star = await call("/sub", { headers: { "if-none-match": "*" } });
  await test("* 通配命中 304", () => assert.equal(star.status, 304));
  const miss = await call("/sub", { headers: { "if-none-match": '"deadbeef"' } });
  await test("异值条件回全量 200", () => assert.equal(miss.status, 200));
}

// ---- 关键键脏数据自愈（审计 G2 盲区）----
{
  freshEnv();
  await send("/api/setup", { password: PW, confirm: PW });
  kv.store.set("warp:device", FAKE_WARP);
  kv.store.set("state:meta", "{not-json");      // 脏 meta
  kv.store.set("settings", "{also-bad");        // 脏 settings
  const r = await call("/sub");
  await test("脏 state:meta + 脏 settings 仍 200（自愈重建不 500）", () =>
    assert.equal(r.status, 200));
  await test("重建出的是新正文而非空", async () =>
    assert.match(await r.text(), /WARP MASQUE/));
}

// ---- 重建失败兜底（P0-A）：regen 抛错宁发旧文不 500 ----
{
  freshEnv();
  await send("/api/setup", { password: PW, confirm: PW });
  kv.store.set("warp:device", FAKE_WARP);
  kv.store.set("config:yaml", "# old-but-good\nproxies: []");
  kv.store.set("state:meta", JSON.stringify({ expiresAt: new Date(Date.now() - 1).toISOString() }));
  // 让 meta 写入失败 → regenConfig 中途抛错
  const origPut = kv.put.bind(kv);
  kv.put = async (k, v) => {
    if (k === "state:meta") throw new Error("kv write down");
    return origPut(k, v);
  };
  const r = await call("/sub");
  await test("regen 失败降级 200 + 旧正文", async () => {
    assert.equal(r.status, 200);
    assert.match(await r.text(), /# old-but-good/);
  });
  await test("失败后重建锁已释放", () => assert.ok(!kv.store.has("rebuild:lock")));
}

// ---- warp:device 四字段校验（P1-6，纯函数单测不联网）----
{
  const good = JSON.parse(FAKE_WARP);
  await test("四字段齐全的存档可用", () => assert.ok(warpUsable(good)));
  for (const field of ["privateKey", "peerPublicKey", "ipv4", "ipv6"]) {
    const broken = { ...good };
    delete broken[field];
    await test(`缺 ${field} 判失效走重注册`, () => assert.ok(!warpUsable(broken)));
  }
  await test("空存档判失效", () => assert.ok(!warpUsable(null)));
}

// ---- 管理 API 收敛（P2-d）：?token= 只留给订阅 ----
{
  freshEnv();
  const s = await send("/api/setup", { password: PW, confirm: PW });
  const sess = { cookie: (s.headers.get("set-cookie") || "").split(";")[0] };
  const freshTok = await mintToken(JSON.parse(kv.store.get("auth:cred")));
  kv.store.set("warp:device", FAKE_WARP);
  await test("有效 query token 也进不了管理路由（无 cookie 404）", async () =>
    assert.equal((await call(`/api/refresh?token=${freshTok}`)).status, 404));
  await test("同一请求带上 cookie 则放行", async () =>
    assert.equal((await send("/api/refresh", {}, sess)).status, 200));
  await test("订阅路由的 ?token= 仍有效（契约保留）", async () => {
    kv.store.set("config:yaml", "# keep-token\nproxies: []");
    kv.store.set("state:meta", JSON.stringify({
      updatedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 3600_000).toISOString(),
      stats: {}, warp: {},
    }));
    assert.equal((await call(`/sub?token=${freshTok}`)).status, 200);
  });
}

// ---- 口令类型与强度（P1-12a + P2-c）----
{
  freshEnv();
  const shortNum = await send("/api/setup", { password: 123, confirm: 123 });
  const shortBody = await shortNum.json();
  await test("数字短口令报长度错误而非不一致", () => {
    assert.equal(shortNum.status, 400);
    assert.match(shortBody.error, /长度/);
    assert.doesNotMatch(shortBody.error, /不一致/);
  });
  const weakPw = await send("/api/setup", { password: "top100top100", confirm: "top100top100" });
  const weakBody = await weakPw.json();
  await test("常见口令被黑名单挡住", () => {
    assert.equal(weakPw.status, 400);
    assert.match(weakBody.error, /常见/);
  });
  const numeric = await send("/api/setup", { password: 123456789012, confirm: 123456789012 });
  await test("同值数字口令（12 位）不再误报 400", () => assert.equal(numeric.status, 200));
}

// ---- 重建锁收敛（P1-7）：refresh / push 也进锁，撞锁 409 不动工 ----
{
  freshEnv();
  const s = await send("/api/setup", { password: PW, confirm: PW });
  const sess = { cookie: (s.headers.get("set-cookie") || "").split(";")[0] };
  kv.store.set("warp:device", FAKE_WARP);
  kv.store.set("config:yaml", "# locked-base\nproxies: []");
  const PTK2 = "pipeline-token-fedcba9876543210";
  kv.store.set("proton:token", PTK2);
  const push2 = (p) => worker.fetch(new Request(`https://x.dev${p}`, {
    method: "POST", headers: { "cf-connecting-ip": "9.9.9.9" }, body: "{}",
  }), env);

  kv.store.set("rebuild:lock", String(Date.now()));   // 他人持锁
  const before = kv.store.get("config:yaml");
  const busyRefresh = await send("/api/refresh", {}, sess);
  await test("refresh 撞锁 409 且不重建", async () => {
    assert.equal(busyRefresh.status, 409);
    assert.equal(kv.store.get("config:yaml"), before);
  });
  const busyPush = await push2(`/push/${PTK2}/rebuild`);
  await test("push 撞锁 409 且不重建", async () => {
    assert.equal(busyPush.status, 409);
    assert.equal(kv.store.get("config:yaml"), before);
  });

  // 并发两路撞他人已持有的锁：全部让路、零重建（互斥语义的确定性断言——
  // KV 无 CAS 原语，裸 put/get 回读在真并发下只保证概率互斥，锁内复读
  // 已把双真窗口压到最小；这里用占位锁验"不重复动工"这条硬性质）
  kv.store.set("rebuild:lock", String(Date.now()));
  let yamlWrites = 0;
  const origPut = kv.put.bind(kv);
  kv.put = async (k, v) => {
    if (k === "config:yaml") yamlWrites++;
    return origPut(k, v);
  };
  const [ra, rb] = await Promise.all([
    send("/api/refresh", {}, sess), send("/api/refresh", {}, sess),
  ]);
  const codes = [ra.status, rb.status].sort();
  await test(`并发 refresh 撞同一把锁全让路 (${codes.join("/")})`, () => {
    assert.deepEqual(codes, [409, 409]);
    assert.equal(yamlWrites, 0);
  });

  // 锁空闲时单路 refresh：抢锁成功、正文恰好写一次、锁已释放
  kv.store.delete("rebuild:lock");
  const solo = await send("/api/refresh", {}, sess);
  await test("锁空闲单路 refresh 成功且写一次正文", () => {
    assert.equal(solo.status, 200);
    assert.equal(yamlWrites, 1);
    assert.ok(!kv.store.has("rebuild:lock"));
  });
}

// ---- ETag 稳定化（P2-a）：数据没变，重建不改正文与指纹 ----
{
  freshEnv();
  await send("/api/setup", { password: PW, confirm: PW });
  kv.store.set("warp:device", FAKE_WARP);
  kv.store.set("proton:token", "pipeline-token-0123456789abcdef");
  kv.store.set("top100:nodes", JSON.stringify([
    { proto: "vless", server: "1.2.3.4", port: 443, ident: "u1", geo: "JP" },
  ]));
  const push3 = (p) => worker.fetch(new Request(`https://x.dev${p}`, {
    method: "POST", headers: { "cf-connecting-ip": "9.9.9.9" }, body: "{}",
  }), env);
  await push3("/push/pipeline-token-0123456789abcdef/rebuild");
  const y1 = kv.store.get("config:yaml");
  const e1 = (await call("/sub")).headers.get("etag");
  await push3("/push/pipeline-token-0123456789abcdef/rebuild");
  const y2 = kv.store.get("config:yaml");
  const e2 = (await call("/sub")).headers.get("etag");
  await test("数据未变时连续重建正文逐字节不变", () => assert.equal(y1, y2));
  await test("数据未变时 ETag 稳定", () => assert.equal(e1, e2));
}

// ---- 改密失败节流（P3-a）：同来源第 9 败转 429，无来源头不启用 ----
{
  freshEnv();
  const s = await send("/api/setup", { password: PW, confirm: PW });
  const sess = { cookie: (s.headers.get("set-cookie") || "").split(";")[0] };
  let last = 0;
  for (let i = 0; i < 9; i++) {
    const r = await send("/api/password",
      { current: "wrong-wrong-1", password: NEW_PW, confirm: NEW_PW }, sess);
    last = r.status;
  }
  await test("同来源第 9 次改密失败改判 429", () => assert.equal(last, 429));
  const noIp = await worker.fetch(new Request("https://x.dev/api/password", {
    method: "POST", headers: sess,
    body: JSON.stringify({ current: "wrong-wrong-1", password: NEW_PW, confirm: NEW_PW }),
  }), env);
  await test("无 CF-Connecting-IP 跳过节流（仍 401，计数不被无来源请求触碰）", async () => {
    assert.equal(noIp.status, 401);
    assert.equal(kv.store.get("rl:9.9.9.9"), "8");
  });
  const ok = await send("/api/password", { current: PW, password: NEW_PW, confirm: NEW_PW }, sess);
  await test("改密成功清零节流计数", () => assert.equal(ok.status, 200));
}

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
