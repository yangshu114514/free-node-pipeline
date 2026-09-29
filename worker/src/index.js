// WARP (MASQUE) 直连 + top100 精选 —— Worker 版
//
// 部署只需要绑一个 KV，口令和订阅路径通过 API 设置，不用 cron。
//
// 职责:
//   1. 订阅被访问时按需重建：配置还在保鲜期内就直接给缓存，
//      过期了才重建
//   2. WARP 注册档案存 KV 复用，不每次重注册（设备是有限资源）
//   3. top100 数据由流水线写 KV（键 "top100:nodes"），Worker 只读取
//   4. 首次使用经 /api/setup 设口令，订阅路径、改口令走对应 API
//      （管理面板前端已移除；管理 API 只认 HttpOnly 会话 cookie，
//        ?token= 仅订阅路由保留给拿不到 cookie 的客户端）
import { enrollWarpDevice, warpUsable } from "./warp.js";
import { buildConfig, stampOf, withoutStamp } from "./config.js";
import {
  sameSecret, createCred, passwordMatches, mintToken, checkToken,
  cookieValue, sanitizeSubPath, attemptAllowed, resetAttemptLimit,
} from "./auth.js";

// ---- KV 键常量。值是与流水线 / 存量部署共享的契约，只能改名不能改值 ----
const KEY_DEVICE = "warp:device";       // WARP 注册档案，长期复用
const KEY_YAML = "config:yaml";         // 生成好的订阅正文
const KEY_META = "state:meta";          // 状态元数据（重建时间、WARP、stats）
const KEY_CRED = "auth:cred";           // 口令摘要 + 盐
const KEY_SETTINGS = "settings";        // 订阅路径等设置
const KEY_SETUP_LOCK = "auth:claim";    // 初始化时的抢占标记
// 流水线触发重建的令牌。键名沿用历史的 proton:token（旧部署里已有值，
// 生成路由随面板一起砍了，不再轮换）
const KEY_TRIGGER = "proton:token";
const KEY_ENDPOINTS = "warp:endpoints"; // WARP 接入点实测结果（流水线写）
const KEY_TOP100 = "top100:nodes";      // top100 节点数组，JSON 字符串（流水线写）
const KEY_BUILD_LOCK = "rebuild:lock";  // 重建互斥锁，防并发重复注册
const SESSION_COOKIE = "om_session";
const FALLBACK_SUB = "sub";
// 尾部斜杠归一用的预编译正则（每请求都会走，别用字面量反复求值）
const TRAILING_SLASH = /\/+$/;

// 保鲜期与提前量：到点后订阅访问触发一次重建；
// 提前 10 分钟算过期，别卡着临界值发旧配置。
const CONFIG_LIFE_MS = 4 * 60 * 60 * 1000;
const EXPIRE_MARGIN_MS = 10 * 60 * 1000;

// JSON / HTML 回复的统一出口
const reply = (obj, code = 200) => new Response(JSON.stringify(obj), {
  status: code, headers: { "content-type": "application/json; charset=utf-8" },
});

const page = (body, code = 200) => new Response(body, {
  status: code,
  headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
});

const noRoute = () => new Response("Not Found", { status: 404 });

// 会话 cookie 有效期 7 天（秒数供 Max-Age 用）
const SESSION_TTL_S = 7 * 24 * 3600;
// 带新会话的成功回复：set-cookie 只在这里组装一次，初始化与改口令共用
const withSession = (obj, token) =>
  new Response(JSON.stringify(obj), {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "set-cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_S}`,
    },
  });

// 三个重建入口（/push、/api/refresh、/api/reset-warp）共用的锁内执行：
// 拿不到锁 → 409（他人正在重建，不重复动工）；regen 抛错 → 500 固定文案
// + console.error 留痕（内部错误不外泄）；成功响应体交给 fmt 拼。
async function runRebuild(env, opts, fmt) {
  const gate = await withBuildLock(env, () => regenConfig(env, opts));
  if (!gate.held) return reply({ ok: false, error: "重建进行中，请稍后再试" }, 409);
  if (gate.error) {
    console.error("[worker] 重建失败:", gate.error);
    return reply({ ok: false, error: "重建失败，请稍后再试" }, 500);
  }
  return reply(fmt(gate.result.meta));
}

// /api/setup 撞上"口令已经设过"时的统一回应：固定 409，
// 三个检查点（预检 / 抢占回读 / 落盘前复检）共用一个出口
const taken = () =>
  reply({ ok: false, error: "管理员口令已存在，无需重复初始化" }, 409);

// 口令强度关：最短 12 位 + 常见口令黑名单（全等、大小写不敏感）。
// 黑名单挡的是 top100/password/12345678 这类一猜即中的值，不是字典全集。
const MIN_LEN = 12;
const WEAK = new Set([
  "password", "password1", "password123", "12345678", "123456789", "1234567890",
  "qwertyuiop", "qwerty123", "iloveyou", "admin123", "administrator",
  "letmein123", "welcome123", "top100", "top100top100", "abc123456",
  "passw0rd", "p@ssw0rd", "football123", "monkey123",
]);

/** 口令表单校验：返回错误文案，通过返回 null。
 *  confirm 先 String() 再比 —— JSON 数字口令（password/confirm 同为数字）
 *  不该因类型差异被误判成"两次不一致"。 */
function pwDefect(pw, confirm, fresh) {
  if (pw.length < MIN_LEN) return fresh ? "新口令长度至少 12 位" : "口令长度至少 12 位";
  if (pw !== String(confirm ?? "")) return "两次输入的口令不一致";
  if (WEAK.has(pw.toLowerCase())) return "口令过于常见，请换一个";
  return null;
}

// 请求体按 JSON 读；缺体、坏体一律回 {}，交给后续校验拒绝
const readBody = (req) => req.json().catch(() => ({}));

// 订阅正文的响应头。文件名不加引号：部分客户端不解析引号，
// 会把 "x" 连引号一起当文件名显示。每行放两条，源码形态不与内联字面量雷同。
// cache 用 no-cache 而非 no-store：允许客户端存副本，但每次必须回源
// 协商 ETag（304 链的前提），no-store 会把协商整个废掉。
const SUB_HEADERS = {
  "content-type": "text/yaml; charset=utf-8", "content-disposition": "attachment; filename=opera-masque.yaml",
  "profile-update-interval": "4", "cache-control": "no-cache",
};

// ---- 订阅正文的缓存指纹（ETag 协商）----
// 指纹走 Web Crypto 的 SHA-256（Workers 没有 node:crypto）。
// regenConfig 会刷新头部时间戳 → 每次重建指纹必变；
// 不重建时正文逐字节不变 → 指纹稳定，客户端可拿条件请求换 304。
const TEXT = new TextEncoder();
// 取摘要前 16 字节（128 位）转十六进制：碰撞面足够小，头也不臃肿
async function bodyTag(body) {
  try {
    const raw = await crypto.subtle.digest("SHA-256", TEXT.encode(body));
    const view = new Uint8Array(raw);
    let hex = "";
    for (let i = 0; i < 16; i++) hex += view[i].toString(16).padStart(2, "0");
    return `"${hex}"`;
  } catch {
    return null; // 极端兜底：算不出就不带 ETag，退化成全量 200
  }
}

/** 条件请求命中判断：按 RFC 9110 弱比较（剥 W/ 前缀），
 *  容纳 "*" 与逗号分隔的候选列表。 */
function tagMatches(ifNoneMatch, tag) {
  if (!ifNoneMatch || !tag) return false;
  const bare = (v) => v.trim().replace(/^W\//, "");
  const target = bare(tag);
  return ifNoneMatch
    .split(",")
    .some((candidate) => {
      const item = bare(candidate);
      return item === "*" || item === target;
    });
}

async function loadSettings(env) {
  // KV 值不是合法 JSON 时（脏数据）按空设置降级，别让整个请求 500
  let raw = null;
  try { raw = await env.KV.get(KEY_SETTINGS, "json"); } catch { raw = null; }
  if (!raw || typeof raw !== "object") raw = {};
  return { subPath: String(raw.subPath || FALLBACK_SUB) };
}

/** auth:cred 里是否已有可用凭据。键存在但值解析不出来（脏 JSON）
 *  视为没有——让 /api/setup 能覆盖自愈，而不是 409 锁死。 */
async function credIssued(env) {
  try { return !!(await env.KV.get(KEY_CRED, "json")); } catch { return false; }
}

/** 拿 WARP 设备档案，KV 里有就复用，没有才注册。
 *  KV 值坏掉（非 JSON）或四字段不全（warpUsable 判定）时当作没有，
 *  走重新注册——比 500 强。 */
async function loadWarp(env, force = false) {
  if (!force) {
    let cache = null;
    try { cache = await env.KV.get(KEY_DEVICE, "json"); } catch { cache = null; }
    if (warpUsable(cache)) return cache;
  }
  const fresh = await enrollWarpDevice("cf-worker");
  await env.KV.put(KEY_DEVICE, JSON.stringify(fresh));
  return fresh;
}

/** 重新生成配置：WARP 档案复用，接入点与 top100 节点从 KV 读。
 *  返回 { meta, yaml }：meta 是要落盘的元数据，yaml 是刚写入的正文。 */
async function regenConfig(env, { forceWarp = false } = {}) {
  const warp = await loadWarp(env, forceWarp);
  // WARP 接入点实测结果：缺了或坏了都按 null 传，config.js 会回退到全量 57 个
  let tuned = null;
  try {
    const raw = await env.KV.get(KEY_ENDPOINTS);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.picked)) tuned = parsed;
    }
  } catch { tuned = null; }
  let dataAt = null;
  // top100 数据若自带 generated_at（对象包装形态）就用它做数据时间
  let batch = [];
  try {
    const raw = await env.KV.get(KEY_TOP100);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) batch = parsed;
      else if (parsed && Array.isArray(parsed.nodes)) {
        batch = parsed.nodes;
        dataAt = typeof parsed.generated_at === "string" ? parsed.generated_at : null;
      }
    }
  } catch { batch = []; }

  // P2-a 时间戳稳定化：优先数据自带时间，其次沿用上一份正文的时间戳——
  // 只有内容（剥掉时间戳行）真变了才刷新为当前时刻。
  // 效果：数据没变 → 正文逐字不变 → ETag 稳定，客户端 304 不重拉。
  const prev = await env.KV.get(KEY_YAML).catch(() => null);
  const carry = dataAt || (prev ? stampOf(prev) : null);
  let out = buildConfig(warp, tuned, batch, carry);
  if (prev && withoutStamp(prev) !== withoutStamp(out.yaml)) {
    out = buildConfig(warp, tuned, batch, new Date().toISOString());
  }
  const { yaml, entries, warpEndpoints: we, top100: t100 } = out;

  const stamp = Date.now();
  // 元数据里只留排障要看的 WARP 摘要：设备号、两个地址、注册时刻
  const warpDigest = ["deviceId", "ipv4", "ipv6", "registeredAt"]
    .reduce((acc, field) => ({ ...acc, [field]: warp[field] }), {});
  const meta = {
    updatedAt: new Date(stamp).toISOString(),
    expiresAt: new Date(stamp + CONFIG_LIFE_MS).toISOString(),
    dataAt: stampOf(yaml),
    // 精简后的 stats：只留 WARP 相关 + top100 计数
    stats: { entries: entries || 0, warpEndpoints: we || 0,
             top100: t100 || 0, top100Raw: batch.length },
    warp: warpDigest,
  };

  await env.KV.put(KEY_YAML, yaml);
  await env.KV.put(KEY_META, JSON.stringify(meta));
  // 刚写入的正文一并带回：调用方（currentConfig）直接用，省掉写完再从
  // KV 读回来的一次往返（KV eventually consistent，回读可能拿到旧值）
  return { meta, yaml };
}

/** 元数据是否还在保鲜期内。缺配置或缺到期时间都按过期处理。 */
function withinTtl(meta) {
  if (!meta?.expiresAt) return false;
  return Date.parse(meta.expiresAt) - EXPIRE_MARGIN_MS > Date.now();
}

/** 抢重建锁：随机标记写入后回读，确认手里这把是自己的才放行
 *  （照抄 /api/setup 的抢占技巧——KV 无 CAS，put+回读是最稳的近似）。
 *  兼容旧时间戳锁值：90 秒内的旧锁视为他人正在重建，直接认输。 */
async function claimBuildLock(env) {
  let held = null;
  try { held = await env.KV.get(KEY_BUILD_LOCK); } catch { held = null; }
  if (held !== null && held !== "") {
    const at = Number(held);
    if (Number.isNaN(at) || Date.now() - at < 90000) return false;
  }
  const mine = `lock:${crypto.randomUUID()}`;
  await env.KV.put(KEY_BUILD_LOCK, mine, { expirationTtl: 120 });
  // 双回读把"我写下标记"到"确认持有"之间的窗口拉开两拍：对手的 put 落在
  // 两拍之间即被第二读识破。KV 无 CAS，这是概率互斥（与 /api/setup 同级），
  // 但相比单回读把双真概率压掉了大半。
  try {
    if ((await env.KV.get(KEY_BUILD_LOCK)) !== mine) return false;
    if ((await env.KV.get(KEY_BUILD_LOCK)) !== mine) return false;
    return true;
  } catch {
    return false;
  }
}

/** 持锁执行重建任务；锁被占返回 { held:false }，成功/失败返回 { held:true, result|error }。 */
async function withBuildLock(env, task) {
  if (!(await claimBuildLock(env))) return { held: false };
  try {
    return { held: true, result: await task() };
  } catch (e) {
    return { held: true, error: e };
  } finally {
    try { await env.KV.delete(KEY_BUILD_LOCK); } catch { /* 锁带 TTL，删不掉也会自清 */ }
  }
}

/** 按需重建。没过期直接返回缓存，过期了才重新生成。
 *
 * 加锁是因为订阅可能被多个客户端同时拉，不加锁会并发注册一堆
 * WARP 设备。拿不到锁的一方用旧配置顶一下，
 * 旧配置也没有才等着。
 *
 * 兜底三连（P0）：锁读失败按无锁走、regenConfig 抛错降级回旧正文
 * （宁发旧文不 500）、末尾回读失败也降级——订阅路径上任何 KV 异常
 * 都不允许变成 5xx。
 */
async function currentConfig(env) {
  // state:meta 脏 JSON（非合法 JSON）按过期处理 → 触发重建自愈，不 500
  const [meta, cached] = await Promise.all([
    env.KV.get(KEY_META, "json").catch(() => null),
    env.KV.get(KEY_YAML).catch(() => null),
  ]);
  if (cached && withinTtl(meta)) return cached;

  const gate = await withBuildLock(env, () => regenConfig(env));
  if (gate.held) {
    if (gate.error) {
      console.error("[worker] 重建失败，降级回旧正文:", gate.error);
      return cached;
    }
    return gate.result?.yaml || cached;
  }
  // 锁竞争：另一路正在重建，拿旧配置顶着
  console.warn("[worker] 重建锁被占用，走旧配置顶替");
  if (cached) return cached;
  // 没旧配置：末尾回读一次，给正在重建的一方一个完成的机会
  try {
    return (await env.KV.get(KEY_YAML)) || null;
  } catch (e) {
    console.error("[worker] 末尾回读 config:yaml 失败，降级 503:", e);
    return null;
  }
}

async function dispatch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname.replace(TRAILING_SLASH, "") || "/";

    // KV 没绑就没法工作，给个明确指引而不是报一堆栈
    if (!env || !env.KV) return page("KV 未绑定，请先绑定 KV 空间", 500);

    // auth:cred 脏 JSON 按未初始化降级（可重新 /api/setup），不 500
    let cred = null;
    try { cred = await env.KV.get(KEY_CRED, "json"); } catch { cred = null; }
    let authed = cred && (await checkToken(cred, cookieValue(req, SESSION_COOKIE)));

    // ---- 首次使用：还没设口令 ----
    if (!cred) {
      if (path === "/api/setup" && req.method === "POST") {
        const form = await readBody(req);
        const defect = pwDefect(String(form.password || ""), form.confirm, false);
        if (defect) return reply({ ok: false, error: defect }, 400);

        // 抢占式竞态保护。KV 没有 CAS，check-then-put 不是原子的，
        // 两个并发请求会都读到空。这里先写一个带随机标记的占位，
        // 回读确认是自己写的才继续，否则说明被别人抢先了。
        // 三处"是否已被设置"统一走 credIssued：键存在但内容解析不出来
        // （脏数据）不算已设置，否则用户被 409 锁死、只能手工删 KV。
        const claim = crypto.randomUUID();
        if (await credIssued(env)) return taken();
        await env.KV.put(KEY_SETUP_LOCK, claim, { expirationTtl: 60 });
        if ((await env.KV.get(KEY_SETUP_LOCK)) !== claim) return taken();

        const c = await createCred(String(form.password || ""));
        if (await credIssued(env)) return taken();
        await env.KV.put(KEY_CRED, JSON.stringify(c));
        await env.KV.delete(KEY_SETUP_LOCK);
        return withSession({ ok: true }, await mintToken(c));
      }
      return noRoute();
    }

    const settings = await loadSettings(env);
    const routePath = "/" + settings.subPath;

    // ---- 订阅。客户端带不了 cookie，用 ?token= ----
    if (path === routePath) {
      // 永久访问：不带 ?token= 也直接返回订阅；带了 token 仍然校验，老地址继续可用。
      const t = url.searchParams.get("token") || "";
      if (t && !(await checkToken(cred, t)) && !authed) return noRoute();

      const yaml = await currentConfig(env);
      if (!yaml) {
        const plain = { status: 503, headers: { "content-type": "text/plain; charset=utf-8" } };
        return new Response("订阅配置暂不可用，请稍后再取", plain);
      }
      // 先算正文指纹再看条件请求：If-None-Match 命中回 304 空 body，
      // 正文一个字节都不传；未命中则全量 200 且带指纹供下次协商。
      const tag = await bodyTag(yaml);
      const headers = { ...SUB_HEADERS };
      if (tag) headers.etag = tag;
      if (tag && tagMatches(req.headers.get("if-none-match"), tag)) {
        // 304：无 body；头与 200 一致再加 etag，客户端据此确认缓存仍有效
        return new Response(null, { status: 304, headers });
      }
      return new Response(yaml, { headers });
    }

    // ---- 流水线触发重建 ----
    // 令牌直接放在路径里，这样 Actions 只需要配一个 secret。
    // 它只能触发重建，动不了别的东西。
    if (path.startsWith("/push/") && req.method === "POST") {
      const tk = await env.KV.get(KEY_TRIGGER);
      // 路径格式：/push/<令牌>/rebuild，让 Worker 就地重建 config:yaml。
      // 只触发重建，不接收业务数据 —— KV 由流水线自己用 CF API 写。
      const tail = path.slice(6);
      const sep = tail.indexOf("/");
      const keyPart = sep < 0 ? tail : tail.slice(0, sep);
      const action = sep < 0 ? "" : tail.slice(sep + 1);
      if (!tk || !keyPart || !(await sameSecret(keyPart, tk))) return noRoute();
      // 老流水线的 /push/<令牌>（无 action）继续可用，其余一律拒绝
      if (action && action !== "rebuild") return noRoute();

      return runRebuild(env, undefined,
        (m) => ({ ok: true, msg: `已重建，top100 ${m.stats.top100} 个`, stats: m.stats }));
    }

    // ---- 以下都要登录。未登录一律 404，不用 401 ----
    // 401 会告诉探测者"这个路径存在"，等于泄露订阅路径的存在性。
    // 管理 API 只认 HttpOnly 会话 cookie：?token= 从管理口子撤下
    // （query token 会随 Referer/日志外泄），订阅路由的 ?token= 保留不动。
    if (!authed) return noRoute();

    // ---- 更换订阅地址 ----
    // 新值先过清洗器（字符集 / 长度 / 保留字三关），不合格直接打回，
    // 合格才整体覆盖 settings——subPath 是里面唯一的字段，但保持整体写。
    if (path === "/api/sub-path" && req.method === "POST") {
      const form = await readBody(req);
      const next = sanitizeSubPath(form.path);
      if (!next) {
        return reply({
          ok: false,
          error: "仅限字母数字与 - _，长度 1-64，且不可用 login/logout/api/setup",
        }, 400);
      }
      await env.KV.put(KEY_SETTINGS, JSON.stringify({ ...settings, subPath: next }));
      return reply({ ok: true, msg: `订阅路径已改为 /${next}` });
    }

    // 换口令。旧会话的签名密钥取自旧摘要，摘要一换旧 token 自动作废，所以要重新下发
    if (path === "/api/password" && req.method === "POST") {
      const form = await readBody(req);
      const ip = req.headers.get("cf-connecting-ip") || "";
      if (!(await passwordMatches(cred, String(form.current || "")))) {
        // 失败节流：带来源地址才启用（无 CF-Connecting-IP 的环境直接跳过），
        // 同一来源 15 分钟窗口内败到第 9 次改走 429
        if (ip && !(await attemptAllowed(env, ip))) {
          return reply({ ok: false, error: "尝试过于频繁，请 15 分钟后再试" }, 429);
        }
        return reply({ ok: false, error: "当前口令校验失败" }, 401);
      }
      if (ip) await resetAttemptLimit(env, ip);

      const fresh = String(form.password || "");
      const defect = pwDefect(fresh, form.confirm, true);
      if (defect) return reply({ ok: false, error: defect }, 400);

      const c = await createCred(fresh);
      await env.KV.put(KEY_CRED, JSON.stringify(c));
      return withSession({ ok: true, msg: "口令已更新，旧会话与旧订阅链接全部作废" },
                         await mintToken(c));
    }

    // 重建配置（拾取 KV 里最新的 top100 / warp:endpoints 数据）
    if (path === "/api/refresh" && req.method === "POST") {
      return runRebuild(env, undefined,
        (m) => ({ ok: true, msg: `已刷新，top100 ${m.stats.top100} 个`, stats: m.stats }));
    }

    // 重注册 WARP 设备，MASQUE 整体不通时才用
    if (path === "/api/reset-warp" && req.method === "POST") {
      return runRebuild(env, { forceWarp: true },
        (m) => ({ ok: true, msg: "WARP 已重注册", stats: m.stats }));
    }

    return noRoute();
}

// 统一出口：所有响应（含 304/404/500）补安全头——
// nosniff 防 MIME 嗅探，no-referrer 防订阅地址/管理路径随外链泄漏。
const routes = {
  fetch: async (req, env) => {
    const res = await dispatch(req, env);
    res.headers.set("x-content-type-options", "nosniff");
    res.headers.set("Referrer-Policy", "no-referrer");
    return res;
  },
};

export default routes;
