# 架构

两段式：**GitHub Actions 负责纯计算并把结果写进 Cloudflare KV，Cloudflare Worker 负责 7×24 拼装下发**。两边只通过 KV 数据和一个 rebuild 触发 URL 解耦——流水线不需要知道 Worker 怎么拼配置，Worker 也不关心节点是怎么筛出来的。

```
GitHub Actions（定时、纯计算）               Cloudflare（常驻）
┌──────────────────────────────┐            ┌──────────────────────────────┐
│ top100.yml 五阶段筛选         │  写 KV      │ Worker                       │
│   ↓ KV top100:nodes          │ ─────────> │  ├ 读 KV 拼 mihomo yaml      │
│ pipeline.yml WARP端点轮换     │            │  ├ 缓存 config:yaml + ETag   │
│   ↓ KV warp:endpoints        │            │  └ GET /<订阅路径> 下发订阅   │
│ POST /push/<令牌>/rebuild     │ ─────────> │      （按需重建，4h 有效期）   │
└──────────────────────────────┘            └──────────────────────────────┘
                                                          │
                                                          ▼
                                                   mihomo 客户端（Alpha 内核）
```

## 两条独立的配置产出线

1. **订阅分发线（主链路）**：Worker 读 KV 生成配置，客户端拉订阅地址（部署实例形如 `https://<你的域名>/<订阅路径>`，路径本身不写入代码与文档——它是免 token 访问的门槛；代码里默认路径是 `sub`，可经 `/api/sub-path` 改，路径存在 KV `settings` 键里）。这是绝大多数用户走的路。
2. **手动生成线**：`scripts/gen_masque.py` 读 `usque register` 产出的 `config.json`，生成一份独立的 mihomo 全量配置（57 个 MASQUE 接入点 + 完整规则集）和 Shadowrocket 的 `masque://` 链接，由手动触发的 workflow `.github/workflows/warp-masque.yml` 校验并打包成 artifact。产物契约：`warp-masque.yaml`、`warp-masque-shadowrocket.txt`、`usque-config.json`。

两条线共用同一套 WARP 接入点表与 AI 域名表（`worker/src/config.js` 与 `scripts/gen_masque.py` 各持一份，**改动须同步**）。

## 四个 workflow 的分工

| workflow | 触发 | 职责 |
|---|---|---|
| `top100.yml` | 每小时 17 分（UTC）+ 手动 | 五阶段筛选免费节点，写 `top100:nodes`，再触发 rebuild（细节见 [pipeline.md](pipeline.md)） |
| `pipeline.yml` | 每 2 小时（`20 */2 * * *`）+ 手动 | 只做 WARP 接入点实测轮换：`probe_warp.py` → 写 `warp:endpoints` → 触发 rebuild |
| `warp-masque.yml` | 手动 | 注册 WARP 设备并生成手动生成线的配置 artifact（见上） |
| `keepalive.yml` | 每天 3:17 UTC | 防止仓库 60 天无 commit 后 GitHub 自动禁用 schedule（API 方式，不产生空 commit） |

## Worker 请求处理

代码在 `worker/src/index.js`。

- **订阅路径**：`GET /<subPath>`（实际值存 KV `settings`，不在代码/文档中写明）。不带 token 永久可访问；带 `?token=` 则校验，老地址不失效。`?token=` 仅限订阅路由——管理 API 只认 HttpOnly 会话 cookie（query token 会随 Referer/日志外泄）。
- **按需重建**：配置有效期 `TTL = 4h`，提前 `10min`（SKEW）算过期；未过期直接回缓存 `config:yaml`，过期才进重建。重建用 KV 键 `rebuild:lock` 互斥（随机标记 + 回读抢占，锁写入带 120s TTL，兼容旧时间戳锁值 90s 判定窗口），拿不到锁的一方先用旧配置顶着，避免并发重复注册 WARP 设备；`/push/.../rebuild`、`/api/refresh`、`/api/reset-warp` 同样走这把锁（撞锁 409）。重建抛错降级回旧正文（宁发旧文不 500）。
- **重建数据源**：`warp:device`（设备信息复用，不重复注册）、`warp:endpoints`（接入点实测结果，缺失则回退全量 57 个）、`top100:nodes`（缺失/损坏则降级为 `[]`，订阅只剩 WARP 兜底）。
- **管理 API**（需登录，未登录一律 404 以免泄露路径存在性）：`/api/setup` 首次设密码（带 `auth:claim` 抢占标记防竞态；口令 ≥12 位 + 常见口令黑名单）、`/api/sub-path` 改订阅路径、`/api/password` 改密码（失败按来源地址节流：15 分钟窗口第 9 败回 429，成功清零；无 `CF-Connecting-IP` 不启用）、`/api/refresh` 强制重建、`/api/reset-warp` 强制重注册 WARP。

### KV 键全表（以 `worker/src/index.js` 顶部常量为准）

| 键 | 写入方 | 读取方 | 内容 |
|---|---|---|---|
| `top100:nodes` | `top_select.py`（流水线） | Worker rebuild | 精选节点数组 JSON：`proto/server/port/ident/geo/raw`（`geo` 供 Worker 拼节点名） |
| `warp:endpoints` | `cf_kv.py`（pipeline.yml，数据来自 `probe_warp.py`） | Worker rebuild | 接入点实测结果，`picked` 为按延迟排序的节点名 |
| `warp:device` | Worker | Worker | WARP 注册信息（私钥等同账号凭据） |
| `config:yaml` | Worker rebuild | 订阅请求 | 生成好的订阅正文 |
| `state:meta` | Worker rebuild | 订阅请求 | `updatedAt` / `expiresAt` / `dataAt`（数据时间，正文时间戳源）/ `stats` / WARP 摘要 |
| `rebuild:lock` | Worker | Worker | 重建互斥锁（带过期 TTL） |
| `auth:cred` | `/api/setup`、`/api/password` | 每请求 | 密码哈希 + 盐 |
| `auth:claim` | `/api/setup` | `/api/setup` | 初始化抢占标记（60s TTL，KV 无 CAS 的替代方案） |
| `settings` | `/api/sub-path` | 路由 | `{ subPath }`，订阅路径 |
| `proton:token` | 部署时手工设置 | `/push/` 路由 | 流水线触发令牌（键名沿用历史 `proton:token`，生成路由已砍） |

### 触发重建（流水线 → Worker）

```
POST https://<worker>/push/<令牌>/rebuild
```

流水线侧只配一个 secret `WORKER_PUSH_URL`（值为 `https://<worker>/push/<令牌>`），步骤里拼 `"$WORKER_PUSH_URL/rebuild"`。令牌走路径而不是 header，是为了让 Actions 只需要一个 secret；该路由**只能触发重建**，动不了别的数据（业务数据由流水线自己用 CF API 写 KV）。令牌比对用常量时间比较 `sameSecret`（先 SHA-256 摘要化再全长异或，长度差也被抹平），不匹配一律 404。

### ETag / 304 协商

- Worker 对订阅正文算 SHA-256 的**前 16 字节 hex** 作为 ETag（带引号）。
- 客户端带 `If-None-Match` 命中（RFC 9110 弱比较，去 `W/` 前缀，支持 `*` 和多值列表）→ 返回 **304 无 body**，头与 200 一致。
- 正文每次 rebuild 必带生成时间戳 → ETag 必变；不 rebuild 时正文逐字不变 → ETag 稳定，客户端条件请求可换 304。
- 兜底：算不出 ETag（极端情况）就不发该头，退化为全量 200。
- 响应头另有 `content-disposition: attachment; filename=opera-masque.yaml`（文件名不加引号，部分客户端不解析）、`profile-update-interval: 4`、`cache-control: no-cache`（允许缓存但每次回源协商 ETag，304 链的前提）；所有响应统一补 `X-Content-Type-Options: nosniff` 与 `Referrer-Policy: no-referrer`。

## 配置组装（`worker/src/config.js`）

`buildConfig(warp, warpEp, top100Nodes)` → `{ yaml, entries, warpEndpoints, top100 }`。

top100 节点命名规则（`topName`）：**`地区-IP`**（如 `JP-42.51.25.69`），地区取 KV `top100:nodes` 的 `geo` 字段，缺失或非两位国家码兜底 `XX`；同名冲突（同 IP 多端口/协议）依次自动追加 `:端口`、`#序号` 保证唯一。

### WARP 接入点

- 表：4 个 v4（`162.159.198.1/2`、`162.159.199.1/2`）× 4 个 v6（`2606:4700:103::1/2`、`2606:4700:104::1/2`）× 7 个端口（443/500/1701/4500/4443/8443/8095），加 1 个「官方域名」（SNI 用 `zt-masque.cloudflareclient.com`，仍落到 v4 地址）= **57 个**。
- `warp:endpoints` 里 `picked` 命中数 ≥ 4 时按实测精选（官方域名永远保留兜底），否则回退全量。
- **不要往回加** `162.159.194/196/197/204` 段和 v6 的 `102/105` 段：它们回 QUIC 包但 login 失败。

### 6 个策略组（全部极简，只此 6 组）

| 组 | 类型 | 成员（top100 非空时） | 成员（top100 为空时） |
|---|---|---|---|
| `WARP直连` | url-test（interval 300 / tolerance 50 / lazy；https 测速 + expected-status 204 + timeout 5000 + max-failed-times 3） | 接入点列表（probe_warp 5 次全过才进 picked，抖动剔除） | 同左 |
| `top100` | url-test（interval 180 / tolerance 100 / lazy true；https 测速 + expected-status 204 + timeout 5000 + max-failed-times 3） | 精选节点 | **整组不生成**，其它组也不得引用它 |
| `🚀 节点选择` | select | `WARP直连`、`top100` | 只有 `WARP直连` |
| `🤖 AI服务` | select | `top100` → `WARP直连` → `🚀 节点选择` | `WARP直连` → `🚀 节点选择` |
| `🎥 奈飞视频` | select | 同 AI服务 | 同左 |
| `🐟 漏网之鱼` | select | `🚀 节点选择` → `top100` → `WARP直连` | `🚀 节点选择` → `WARP直连` |

所有成员只允许指向**存在的**组/节点，空 top100 时不留悬空引用（否则 mihomo 拒载）。

### 分流规则（四类，共 115 条）

顺序固定，先命先生效：

1. **AI**：102 条内联 `DOMAIN-SUFFIX,<域名>,🤖 AI服务`（手写表，只收各家自有域名——不能加 `googleapis.com`、`cloudflare.com` 这类共用域名，会把无关流量拽进 AI 组）+ 6 个 AI 规则集 `RULE-SET`。内联域名排在 `RULE-SET` **前面**，防止上游更宽的条目抢先命中；**关键主域（chatgpt.com/openai.com 等）必须内联**——RULE-SET 是 24h 外部拉取，下载窗口内裸主域会漏到 GEOIP 段偶发直连（线上 ERR_SSL_PROTOCOL_ERROR 实锤过）。
2. **奈飞**：1 个 `RULE-SET` → `🎥 奈飞视频`。
3. **局域网 + 中国**：3 个 `RULE-SET`（LocalAreaNetwork / ChinaDomain / ChinaCompanyIp）→ `DIRECT`，加 `GEOIP,LAN,DIRECT,no-resolve`、`GEOIP,CN,DIRECT`。
4. **兜底**：`MATCH,🐟 漏网之鱼`。

规则集共 **10 个**（`interval: 86400` 每日拉新）。广告净化、微软、苹果、电报、油管、FCM、Steam 等分组已全部砍掉——用不到的规则集只会拖慢 mihomo 启动。（102 + 10 + 3 = 115 条规则。）

## 链式代理（核心设计）

`top100` 组内**每个节点都带 `dialer-proxy: "WARP直连"`**：

```
直连（死路）:  本机 ──被墙──> 免费节点 ──> 目标            实测 1/100 稳定
链式（可行）:  本机 ──稳定──> WARP ──海外直连──> 节点 ──> 目标   实测 44/100 稳定
```

**为什么**：国内直连免费节点约 99% 被墙——TCP 握手通但传输被掐（表现为 `ERR_SSL_PROTOCOL_ERROR`）。改走 WARP 隧道后第二段变成海外 → 海外，绕开被掐的段。代价是延迟翻倍（主力 200–500ms）。

**成环风险（改动 dialer-proxy 前必读）**：

- `dialer-proxy` **必须指 `WARP直连`**，不能指成员包含 top100 自身的组（比如自动选择类 url-test 组）。一旦指向，url-test 把 top100 选中时会形成 `dialer → 组 → top100 → dialer` 的环，**mihomo 直接拒连甚至崩内核**。仓库里有对应的防回归断言。
- dialer 走的是**整组** `WARP直连`（组内含 v6 接入点）。历史版本曾在 `assembleEndpoints` 里另组一份仅 IPv4 的 `v4Entries` 备上层选用（纯 IPv4 机器拿 v6 地址建 dialer 会 `network is unreachable`）——现 `buildConfig` 从不消费它，该死组装已删除；若将来改用单地址做 dialer 目标，需重新引入并同时覆盖这条约束。
- 客户端注意：Clash Verge 的「链式代理」开关会清除订阅里的 `dialer-proxy`（其 issue #6426），不要点。

## 手动生成线产物（`scripts/gen_masque.py`）

输入 `usque` 的 `config.json`（私钥可能是 PEM，脚本会剥壳成裸 base64；公钥同理），输出：

- `warp-masque.yaml`：57 节点 + 16 个策略组 + 27 个规则集的完整 mihomo 配置（这份是手动生成线的全量版，与 Worker 的 6 组极简版不同）。
- `warp-masque-shadowrocket.txt`：8 地址 × 7 端口 = 56 条 `masque://` 链接，参数与字段名对齐 Shadowrocket 实现（`publicKey` 用剥壳 base64 DER，`privateKey` 用 usque 原值，逗号不转义）。

`warp-masque.yml` 里还会用 mihomo Alpha 内核 `-t` 做一次加载校验后打包上传 artifact。
