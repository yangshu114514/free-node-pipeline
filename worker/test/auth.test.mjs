// 鉴权底层测试。跑: node test/auth.test.mjs
import assert from "node:assert/strict";
import {
  sameSecret, createCred, passwordMatches, mintToken, checkToken,
  attemptAllowed, resetAttemptLimit, sanitizeSubPath,
} from "../src/auth.js";

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

// ---- 恒定耗时比较 ----
await test("同串判定相等", async () => assert.equal(await sameSecret("abc", "abc"), true));
await test("改一位即不等", async () => assert.equal(await sameSecret("abc", "abd"), false));
await test("长度差一位也不等", async () => assert.equal(await sameSecret("abc", "abcd"), false));
await test("空串对非空不等", async () => assert.equal(await sameSecret("", "x"), false));

// ---- 凭据：口令只存摘要 ----
const cred = await createCred("correct-horse-battery");
await test("存档里找不到口令原文", () =>
  assert.ok(!JSON.stringify(cred).includes("correct-horse-battery")));
await test("每次存档的盐都不同", async () => {
  const [s1, s2] = [await createCred("same"), await createCred("same")];
  assert.notEqual(s1.salt, s2.salt);
});
await test("原口令核验通过", async () =>
  assert.ok(await passwordMatches(cred, "correct-horse-battery")));
await test("换了口令核验不过", async () =>
  assert.ok(!(await passwordMatches(cred, "wrong"))));
await test("空口令核验不过", async () =>
  assert.ok(!(await passwordMatches(cred, ""))));
await test("没有存档直接判否", async () =>
  assert.ok(!(await passwordMatches(null, "x"))));

// ---- 会话凭证 ----
const tok = await mintToken(cred);
await test("签发的凭证可用", async () => assert.ok(await checkToken(cred, tok)));
await test("动过签名即作废", async () =>
  assert.ok(!(await checkToken(cred, tok.slice(0, -2) + "xy"))));
await test("换时间戳但签名对不上即作废", async () =>
  assert.ok(!(await checkToken(cred, "99999999999999." + tok.split(".")[1]))));
await test("过了失效时刻的凭证作废", async () =>
  assert.ok(!(await checkToken(cred, "1000000000000.abc"))));
await test("空凭证作废", async () => assert.ok(!(await checkToken(cred, ""))));
await test("没有分隔点的凭证作废", async () =>
  assert.ok(!(await checkToken(cred, "garbage"))));

const cred2 = await createCred("new-password-here");
await test("换口令后旧凭证作废", async () =>
  assert.ok(!(await checkToken(cred2, tok))));

// ---- 订阅路径清洗 ----
await test("普通段原样通过", () =>
  assert.equal(sanitizeSubPath("a8f3d91c"), "a8f3d91c"));
await test("首尾斜杠剥掉", () => assert.equal(sanitizeSubPath("/my-sub/"), "my-sub"));
await test("空输入拒绝", () => assert.equal(sanitizeSubPath(""), null));
await test("内嵌斜杠拒绝", () => assert.equal(sanitizeSubPath("a/b"), null));
await test("带空格拒绝", () => assert.equal(sanitizeSubPath("a b"), null));
await test("保留段 api 拒绝", () => assert.equal(sanitizeSubPath("api"), null));
await test("保留段大小写不分", () => assert.equal(sanitizeSubPath("LOGIN"), null));
await test("超长段拒绝", () => assert.equal(sanitizeSubPath("x".repeat(65)), null));

// ---- 失败节流 ----
const kv = { m: new Map(),
  async get(k) { return this.m.get(k); },
  async put(k, v) { this.m.set(k, v); },
  async delete(k) { this.m.delete(k); } };
let allowed = 0;
for (let i = 0; i < 12; i++) if (await attemptAllowed({ KV: kv }, "1.2.3.4")) allowed++;
await test(`连试 12 次只放行 8 次 (实际 ${allowed})`, () => assert.equal(allowed, 8));
await resetAttemptLimit({ KV: kv }, "1.2.3.4");
await test("清除记录后重新放行", async () =>
  assert.ok(await attemptAllowed({ KV: kv }, "1.2.3.4")));

console.log(`\n通过 ${pass} 失败 ${fail}`);
if (fail) process.exit(1);
