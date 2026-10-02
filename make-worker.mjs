// make-worker.mjs — 把 esbuild 产物 worker/dist/worker.js (ESM)
// 转成 Service Worker 单文件（self.addEventListener('fetch') 形态，供网页方式部署）。
// 只做唯一必须的一步：ESM 默认导出 → fetch 监听，避免对 dist 逐条打补丁与 src 脱节。
//
// 用法: node make-worker.mjs [输出路径]
//   默认读 worker/dist/worker.js，写出 worker/dist/worker.sw.js
// 前置: npx esbuild worker/src/index.js --bundle --format=esm --target=es2022 --outfile=worker/dist/worker.js
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";

const ROOT = dirname(fileURLToPath(import.meta.url));
const DIST = join(ROOT, "worker", "dist", "worker.js");
const OUT = process.argv[2] ? resolve(process.argv[2]) : join(ROOT, "worker", "dist", "worker.sw.js");
const TAIL = "export {\n  index_default as default\n};";
const SW = "self.addEventListener('fetch', (event) => { event.respondWith(index_default.fetch(event.request, { KV: KV })); });\n";

if (!existsSync(DIST)) {
  console.error(`找不到 ${DIST}，先跑: npx esbuild worker/src/index.js --bundle --format=esm --target=es2022 --outfile=worker/dist/worker.js`);
  process.exit(1);
}

let s = readFileSync(DIST, "utf8").replace(/\s+$/, "");
if (!s.endsWith(TAIL)) {
  console.error("dist 尾部不是预期的 ESM 导出结构，中止（避免部署坏产物）");
  process.exit(1);
}
s = s.slice(0, -TAIL.length) + SW;

// 自检：架构关键特征必须在产物里，已砍的源不许回魂
const mustHave = [
  ["读取 top100:nodes", /top100:nodes/],
  ["buildConfig 新三参 top100Nodes", /top100Nodes/],
  ["WARP直连 组保留", /name: WARP|WARP\\u76F4\\u8FDE/],
  ["订阅免 token", /searchParams\.get\("token"\)/],
  // 加密 DNS：境内阿里 DoH / 境外 Cloudflare DoH 且指定 WARP 出口 / 隧道内 DNS 也是 DoH
  ["DNS：境内阿里云 DoH", /https:\/\/223\.5\.5\.5\/dns-query/],
  ["DNS：境外 CF DoH 指定 WARP 出口", /dns-query#WARP/],
  ["DNS：masque 隧道内 DoH", /dns: \['https:\/\/1\.1\.1\.1\/dns-query'/],
];
const mustNotHave = [
  ["Proton 源已砍", /proton:cred/],
  ["Windscribe 源已砍", /wind:account/],
  ["ip2free 源已砍", /ip2free:nodes/],
  ["面板前端已砍", /renderUI/],
  // 明文 DNS 回魂：旧 bootstrap 的 119.29.29.29 与裸 IP 形式的 masque dns
  ["明文 bootstrap DNS 已清除", /119\.29\.29\.29/],
  ["masque 明文 IP DNS 已清除", /dns: \[1\.1\.1\.1/],
];
let bad = 0;
for (const [label, re] of mustHave) {
  const ok = re.test(s);
  if (!ok) bad++;
  console.log(`  [${ok ? "ok" : "缺失"}] ${label}`);
}
for (const [label, re] of mustNotHave) {
  const ok = !re.test(s);   // 应当不含
  if (!ok) bad++;
  console.log(`  [${ok ? "ok" : "残留"}] ${label}`);
}
if (bad) {
  console.error(`有 ${bad} 项关键检查未通过，中止部署`);
  process.exit(1);
}

writeFileSync(OUT, s);
console.log(`已生成 ${OUT}（${s.length} 字符，${Math.round(s.length / 1024)}KB）`);
