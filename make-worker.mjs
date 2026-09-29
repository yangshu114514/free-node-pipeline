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
];
const mustNotHave = [
  ["Proton 源已砍", /proton:cred/],
  ["Windscribe 源已砍", /wind:account/],
  ["ip2free 源已砍", /ip2free:nodes/],
  ["面板前端已砍", /renderUI/],
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
