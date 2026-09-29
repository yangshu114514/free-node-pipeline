# free-node-pipeline

免费代理节点聚合订阅服务：**99 个源自动抓取 → 五阶段流水线筛选 → Cloudflare Worker 分发 mihomo 订阅**，附 WARP 链式中转绕墙。全程无人值守，每小时自动更新一轮。

## 架构

```
GitHub Actions（每小时 17 分，纯计算）        Cloudflare（7×24 常驻）
┌──────────────────────────────────┐        ┌─────────────────────────────┐
│ 1. 抓取   99 源 → 43.7万去重池   │        │  Worker                     │
│ 2a. TCP   asyncio 节流全量测     │  写入  │  ├─ KV top100:nodes (筛选结果)│
│ 2b. 协议  8×mihomo 初筛          │ ─────> │  ├─ KV warp:endpoints (端点) │
│ 3. 纯净度 ip-api 国别/代理判定   │  KV    │  └─ 生成 mihomo yaml → 订阅  │
│ 4. 优选   打分取 top100 → 写 KV  │        │      GET /<订阅路径>          │
│ 5. 重建   POST /push/.../rebuild │        └─────────────────────────────┘
└──────────────────────────────────┘                    │
        每步独立脚本（.github/scripts/top_*.py）         ▼
                                              mihomo 客户端（全平台）
```

数据流：**流水线只产出数据进 KV，Worker 只负责拼装下发**——两者通过 `top100:nodes`（含完整 raw URI）和 rebuild 触发解耦。

## 订阅使用

- **订阅地址**：`https://<你的域名>/<订阅路径>`（订阅路径自定、不在代码与文档中写明，可在 Worker 管理界面修改——路径即访问门槛，**别公开贴出**）
- **内核要求**：mihomo **Alpha** 分支（订阅含 `masque` 类型节点，稳定版会拒载）

导入后你会看到这些组：

| 组 | 类型 | 说明 |
|---|---|---|
| `WARP直连` | url-test | WARP MASQUE 接入点自动选最快（实测精选 picked≤12，缺失时回退全量 57），**出口是 CF IP，国内直连保底** |
| `top100` | url-test | 精选节点，**全部走链式**（见下），可换出口国家 |
| `🚀 节点选择` | selector | 总开关：WARP直连 / top100 手动切换 |
| `🤖 AI服务` | selector | 分流：AI 站点（建议选 top100，OpenAI 等封 CF IP，WARP 直连会握手失败）|
| `🎥 奈飞视频` | selector | 分流：流媒体 |
| `🐟 漏网之鱼` | selector | 兜底：未匹配流量（默认走节点选择）|

规则只有四类：**AI → 奈飞 → 局域网/国内直连 → 兜底**，其余服务分组全部砍掉（规则 115 条、规则集下载 10 个，mihomo 启动快）。

## 链式代理（核心设计）

`top100` 的每个节点都带 `dialer-proxy: WARP直连`：

```
直连（死路）:  本机 ──被墙──> 免费节点 ──> 目标      实测 1/100 可用
链式（可行）:  本机 ──稳定──> WARP ──海外直连──> 节点 ──> 目标   实测 44/100 稳定
```

国内直连免费节点 99% 被墙（握手通但传输被掐，表现为 `ERR_SSL_PROTOCOL_ERROR`）；改走 WARP 隧道后第二段变成海外→海外，绕开墙。代价是延迟翻倍（主力 200-500ms）。

> **注意**：Clash Verge 的"链式代理"按钮会清除订阅里的 `dialer-proxy`（见其 issue #6426），
> 不要点它；如果点了导致链式失效，用 Verge 的 Script 功能重新注入即可。

## 性能基线（Actions ubuntu-latest 实测）

| 步骤 | 耗时 | 关键手段 |
|---|---|---|
| 抓取 99 源 | ~1 min | keep-alive 连接池、单源 10s 熔断、48 源并发 |
| TCP 粗筛 43.7万 | ~1.6 min | asyncio + pacer 节流 3000/s（防 SYN 洪峰丢包）、端点去重回填 |
| 协议初筛 5万 | ~2.5 min | 8 实例并行 `-t` 预检、delay 超时 5s、512 并发、出口证书自证剔除 MITM 假证书出口 |
| 纯净度 + 优选写 KV | ~10 s | ip-api 5 并发 + 45/min 限速 |
| **总计** | **~5.5 min** | 基线 20.5 min → 优化 3.8 倍 |

速率纪律：本机家宽安全建连速率实测 ≈700/s，Actions 机房 3000/s（4000 开始排队）——
**瓶颈是出口 pps 不是语言**，换 Rust/C 也快不过它。

## 目录结构

```
.github/
  workflows/    top100.yml（主水线）pipeline.yml（WARP端点轮换）keepalive.yml（保活）warp-masque.yml（手动生成线）
  scripts/      top_collect/top_tcp/top_proto/top_purity/top_select 五段独立脚本
                cf_kv.py（KV 读写）probe_warp.py（端点实测）
worker/
  src/          index.js（路由/缓存/锁）config.js（配置组装/规则/节点转换）
                auth.js warp.js
  test/         config/route/auth 三套测试（174 项）
docs/           技术文档（架构与流水线详解）
scripts/        gen_masque.py（MASQUE 配置生成）
```

每个流水线脚本可**独立重跑**（产物 json 落盘，跑下一步不必重跑上一步）。

## 本地开发

```bash
# Worker 测试（174 项）
node --test worker/test/config.test.mjs
node --test worker/test/route.test.mjs
node --test worker/test/auth.test.mjs

# 构建 + 校验 + 部署
npx esbuild worker/src/index.js --bundle --format=esm --target=es2022 --outfile=worker/dist/worker.js
node make-worker.mjs        # 产物断言（已砍的旧源不许回魂）+ 生成网页部署用 worker/dist/worker.sw.js（可传参指定输出路径）
# wrangler 部署：配置在 worker/wrangler.toml（main = "src/index.js"），在 worker/ 目录内执行 npx wrangler deploy

# 流水线单步重跑（需要 CLOUDFLARE_API_TOKEN 等 env，详见各脚本头部注释）
python .github/scripts/top_tcp.py       # 读 node_pool.json → tcp_cands.json
python .github/scripts/top_proto.py     # 读 tcp_cands → latency.json
```

## 技术文档

- [架构总览](docs/architecture.md) —— 两条配置产出线、KV 键表、订阅分发与缓存协商（ETag/304、4h TTL、重建锁）、6 策略组与规则体系、链式代理防环
- [流水线详解](docs/pipeline.md) —— 五阶段输入输出与全部参数、打分与可用性门槛、耗时基线（20.5min → 5.45min）、单步重跑

## 许可

[Apache License 2.0](LICENSE)
