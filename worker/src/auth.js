// 登录与会话管理。口令只落 KV，不进环境变量。
//
// 设计要点：
//   - KV 里存的是 PBKDF2 摘要 + 盐，明文口令任何地方都不落地
//   - 会话凭证用"摘要当密钥"签名：换口令 → 摘要变 → 旧凭证集体作废
//   - 比较一律走摘要化 + 全长扫描，耗时与内容无关，防时序侧信道
//   - 失败尝试按来源地址节流，否则弱口令几分钟就被穷举出来
const utf8 = new TextEncoder();

// 派生轮数：210k 在 Workers 上约百毫秒量级——登录可感知但不难受，
// 离线爆破成本翻倍有余（存量存档带 iter 字段，历史口令仍按旧轮数核验）
const ROUNDS = 210000;

const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

const fromBase64 = (s) =>
  Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));

async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(text)));
}

/**
 * 恒定耗时的字符串相等判断。
 *
 * 先把两边各自 SHA-256 成等长摘要，再整段扫描异或：
 * 连长度差异都被摘要抹平，比较耗时只由固定的 32 字节决定。
 */
export async function sameSecret(a, b) {
  const [x, y] = await Promise.all([sha256(a || ""), sha256(b || "")]);
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= x[i] ^ y[i];
  return acc === 0;
}

/** PBKDF2 拉伸：口令 + 盐 + 轮数 → 256 位摘要（base64 文本）。 */
async function stretch(plain, saltText, times = ROUNDS) {
  const mat = await crypto.subtle.importKey(
    "raw", utf8.encode(plain), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromBase64(saltText), iterations: times, hash: "SHA-256" },
    mat, 256);
  return toBase64(bits);
}

/** 建一份凭据记录 —— 这个对象就是 KV `auth:cred` 的存档格式。 */
export async function createCred(plain) {
  const seed = crypto.getRandomValues(new Uint8Array(16));
  const salt = toBase64(seed);
  return {
    salt,
    iter: ROUNDS,
    hash: await stretch(plain, salt, ROUNDS),
    updatedAt: new Date().toISOString(),
  };
}

export async function passwordMatches(cred, plain) {
  if (!cred?.hash) return false;
  const recalc = await stretch(plain, cred.salt, cred.iter || ROUNDS);
  return sameSecret(recalc, cred.hash);
}

async function signWith(keyText, payload) {
  const key = await crypto.subtle.importKey(
    "raw", utf8.encode(keyText), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, utf8.encode(payload));
  return toBase64(mac).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// 会话有效期 7 天
const SESSION_MS = 7 * 24 * 3600 * 1000;

/** 签发会话凭证：`过期时刻.签名`。签名密钥取自口令摘要，
 *  所以改口令即吊销全部旧会话，无需维护吊销名单。 */
export async function mintToken(cred) {
  const deadline = Date.now() + SESSION_MS;
  return `${deadline}.${await signWith(cred.hash, String(deadline))}`;
}

export async function checkToken(cred, token) {
  if (!cred?.hash || !token) return false;
  const cut = token.lastIndexOf(".");
  if (cut < 1) return false;
  const deadline = token.slice(0, cut);
  const mac = token.slice(cut + 1);
  if (!/^\d+$/.test(deadline) || Number(deadline) < Date.now()) return false;
  return sameSecret(mac, await signWith(cred.hash, deadline));
}

/** 从 Cookie 头里取指定名字的值；没有返回 null。 */
export function cookieValue(req, name) {
  const header = req.headers.get("cookie") || "";
  for (const pair of header.split(";")) {
    const eq = pair.trim().indexOf("=");
    if (eq > 0 && pair.trim().slice(0, eq) === name) return pair.trim().slice(eq + 1);
  }
  return null;
}

const LIMIT_KEY = (ip) => `rl:${ip}`;
const MAX_TRIES = 8;
const LOCK_TTL = 900;   // 秒：15 分钟窗口

/** 失败节流：同一来源 15 分钟内放行 8 次，第 9 次起拒绝。 */
export async function attemptAllowed(env, ip) {
  const hits = Number((await env.KV.get(LIMIT_KEY(ip))) || 0);
  if (hits >= MAX_TRIES) return false;
  await env.KV.put(LIMIT_KEY(ip), String(hits + 1), { expirationTtl: LOCK_TTL });
  return true;
}

export async function resetAttemptLimit(env, ip) {
  await env.KV.delete(LIMIT_KEY(ip));
}

// 与路由段撞名的订阅地址直接拒掉（/api、/login 这类）
const RESERVED = new Set(["login", "logout", "api", "setup"]);
const SUB_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;

/** 规整订阅路径：去首尾斜杠、只留 [A-Za-z0-9_-] 1~64 位、避开保留字。
 *  不合格返回 null，由调用方决定怎么报错。 */
export function sanitizeSubPath(input) {
  const seg = String(input || "").trim().replace(/^\/+|\/+$/g, "");
  if (!seg || !SUB_PATTERN.test(seg)) return null;
  return RESERVED.has(seg.toLowerCase()) ? null : seg;
}
