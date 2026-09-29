# 流水线细节（top100.yml）

每小时 17 分（UTC，错开整点避开高峰）跑一遍，也可手动触发。job 约束：`concurrency: top100-nodes`（不取消进行中的运行）、`timeout-minutes: 45`、`ubuntu-latest` + Python 3.12 + `pip install requests==2.34.2`（依赖钉死不浮动）。

**每个阶段是独立脚本**（`.github/scripts/top_*.py`），产物 json 落盘在仓库根，跑下一步不必重跑上一步——单步重跑只需按顺序准备上一步的输入文件。

```
sources_active.json（99 源）
   │ 1. top_collect.py
   ▼
node_pool.json ──▶ 2a. top_tcp.py ──▶ tcp_cands.json
                        │  2b. top_proto.py
                        ▼
                  latency.json ──▶ 3. top_purity.py ──▶ purity.json
                                        │  4. top_select.py
                                        ▼
                          top100_detail.json / top100_summary.json
                          + KV top100:nodes ──▶ 5. POST rebuild
```

## 阶段 1：抓取 — `top_collect.py`

- **输入**：`sources_active.json`（99 个活跃源）。
- **输出**：`node_pool.json`，节点格式 `{proto, server, port, ident, raw}`，`raw` 是完整原始 URI（含 sni/tls/network/path），下游协议测与 Worker 转换都从 `raw` 恢复参数。
- **做什么**：每源先抓 README 找额外订阅 URL，再试 ≤8 个候选路径；多格式解析（vmess/ss/vless/trojan/hysteria2/hy2/tuic + base64 文本 + 裸 `IP:port` 列表）；按 `(proto, server, port, ident)` 去重并过滤非法地址（回环/私网/链路本地/保留/多播）。
- **关键参数**（脚本顶部常量，改动看 `[诊断]/[最慢源]` 输出校准）：

  | 常量 | 值 | 含义 |
  |---|---|---|
  | `SOURCE_WORKERS` | 48 | 源级并发，波数 ≈ ceil(99/48) = 3 |
  | `PATH_WORKERS` | 192 | 全局取文本线程池，线程局部 keep-alive Session 跨源复用连接 |
  | `SOURCE_BUDGET` | 10 s | 单源总耗时预算，超时熔断放弃剩余路径 |
  | `T_README` / `T_PATH` | (3,5) / (4,8) s | 连接/读超时；404 即时返回不受影响，挂起源 2–3 倍速放弃 |

- **耗时**：~1 min。优化要点：连接从每请求新建改为线程局部复用（握手 ~1100 次 → ~192 次）、单源预算熔断、每源耗时/状态统计排行。
- 本机测试可 `PROXY=http://127.0.0.1:7897 python top_collect.py`。

## 阶段 2a：TCP 粗筛 — `top_tcp.py`

- **输入**：`node_pool.json` → **输出**：`tcp_cands.json`（存活节点带 `tcp_rtt`）。
- **做什么**：asyncio 单事件循环高并发 TCP 握手测可达 + RTT；按 `(host, port)` 聚合同端点只测一次，结果回填组内全部条目（43.7 万池 → 38.3 万唯一端点，省 12.6% 连接）；`SO_LINGER=0` 发 RST 关闭，不占 TIME_WAIT 端口。
- **关键参数**：

  | 参数 | 值 | 含义 |
  |---|---|---|
  | `TCP_PACE`（env，top100.yml 设） | **3000** 连接/s | 每秒新建连接数，pacer 严格均匀放行。4000 时 med 174ms 已现排队，3000 留余量；脚本内默认 700 是家宽安全值 |
  | `TCP_CONC`（env） | 6000 | 同时挂起连接上限（保险丝），稳态 ≈ PACE × 平均耗时 |
  | `TCP_TIMEOUT` | 1.5 s | **不要为提速降**：协议活节点 rtt 中位数 955ms，500ms 内仅 46%，收紧会砍真节点 |
  | `TCP_SAMPLE` | 0（全量） | >0 时随机抽样（对照实验用，种子 42） |
  | `TCP_TOP` | 0 | 0 = TCP 存活全进协议初筛；>0 按 rtt 截断 |

- **耗时**：~1.6 min。速率纪律：瓶颈是出口 pps（conntrack / 网卡 tx 队列 / NAT / 对端 ingress），不是语言；洪峰式 12000 瞬发实测把出口打崩。

## 阶段 2b：协议初筛 — `top_proto.py`

- **输入**：`tcp_cands.json` → **输出**：`latency.json`（前 1000，带 `delay`）。
- **做什么**：把节点转成 mihomo clash 节点，起多个 mihomo 实例分片并行，用真实请求（`http://www.gstatic.com/generate_204`）测协议延迟，淘汰「协议死」的假节点。协议活节点再过**出口证书自证**：对 `CERT_URLS` 的 https 目标追加 delay 探测——mihomo 对 https 会验证目标 TLS 证书链与域名，出口异常（假证书/隧道终结/443 明文）握手直接失败（状态码不参与判定，200/403/403 挑战页均算过）；任一目标首测 fail → **等 `CERT_RETRY_GAP=2s`** 复测一次（滤 MASQUE 秒级抖动窗口，立即复测会把抖动节点双杀），复测仍 fail 且**错误非 Timeout** 才判「作恶/劣质出口」剔除（超时=网络抖动不踢，假证书/握手错=快速失败才踢；`latency.json` 记 `cert_kicked`，日志打原因 top、timeout 豁免数与被剔 raw 样例）。**剔除实锤**：第二轮剔 372/1006，日志样例 3/3 本机复现——443 上 TLS 握手全部 `WRONG_VERSION_NUMBER`（对端回明文不回 TLS，即「只通明文 http 的残隧道/假 ss」，用户开任何 https 必死），其中含已实锤劫持节点 `104.129.164.30`。**为什么必须单独一步**：实测劫持节点对 gstatic 是 SNI 白名单放行的（测速 URL 发现不了）。可单独重跑，复用 2a 结果。
- **关键参数**：

  | 参数 | 值 | 含义 |
  |---|---|---|
  | `PROTO_MAX`（env，默认 30000） | 30000 | 输入抽样上限：云端 TCP 存活 15w+，按 `tcp_rtt` **等距抽样**截断——不能只取最快（最快多是 CF 假节点，活率 0.15%），等距覆盖快中慢保住「慢而真」（全量口径 4.7%）。3 万的推算：4.7% × 3w ≈ 1410 协议活，三层漏斗后约 650 > 100 名额，余量充足且整轮再省约 50 s |
  | `MIHOMO_SHARDS`（top100.yml 设） | **8** | 分片实例数（脚本默认 4）；`-t` 预检与启动并行，控制端口从 9097 起按片递增 |
  | `DELAY_TMO` | 5000 ms | 成功节点 delay max 4107ms，5s 无损；原 12s 让 6631 个死节点各白等 7s |
  | `CERT_URLS` | cloudflare.com + chatgpt.com | 出口证书自证目标（常量）：https delay 校验证书，复测（间隔 `CERT_RETRY_GAP=2s`）仍 fail 且非 Timeout 即剔除；仅对协议活节点探测，成本 ~2800 次请求/轮（512 并发下约 25s） |
  | `TOTAL_DELAY_WORKERS` | 512 | delay 是网络等待不吃 CPU（128→256→512 阶梯实测，见 top_proto 注释） |
  | `TOP_N` | 1000 | 进入下一阶段的数量 |
  | `ALIVE_FLOOR` | 100 | **交付下限**：筛后进入下一阶段的节点 < 100 → `::error::` + exit 1（`latency.json` 仍落盘供诊断，防止塌方轮静默传给下游） |

- **回退**：全部分片起不来时回退 TCP-only（按 `tcp_rtt` 排序），不让流水线死在这里。
- **耗时**：~2.5 min。

## 阶段 3：纯净度 — `top_purity.py`

- **输入**：`latency.json`（前 1000）→ **输出**：`purity.json`（节点追加 `geo/exit_ip/is_proxy/is_hosting/isp/as`）。
- **做什么**：免费单机代理的出口 IP == 节点服务器 IP，所以直查 `node.server` 等价于查出口。`server` 是**域名**的先 DNS 解析成 A 记录 IP 再查（16 并发，同 IP 的多个域名合并成一次查询、返回时按原 server 还原键；解析失败按原值交查询层报错占位）——域名直接传给查询层必 `invalid query`，geo 会全丢。**三层查询链逐层降级、任何层失败都不红，全链零 secret 零 key**：① 主力 `ip-api.com/batch`（现有实现原样：HTTP 直连 + 45/min 限速 + 指数退避；免费版仅 IPv4，IPv6 不进本层）→ ② 补查 `FFraud` 公开端点 `GET api.ffraud.com/public/ip/<IP>`（免 key 免注册、无日上限仅 burst 限速 429；**单条 GET 串行补查**，两个用途：ip-api 失败批/未查到的 IPv4 逐条补查 + **IPv6 唯一查询通道**——ip-api 免费版不支持 IPv6；每批 ≤100 条、条间隔 0.05s 防 burst 429，**429 跳过当批剩余不重试轰炸**，网络错直接放弃该条走下一层）→ ③ 离线兜底 `_offline_lookup()`（GeoLite2/IP2Proxy LITE 本地 mmdb 思路，**本次只留接口与接入点注释**）→ 仍拿不到填 `err` 占位（保持原 fail 语义）。字段映射：`cc ← geo.country`、`proxy ← proxy`、`hosting ← hosting`、`isp ← organization`、`as ← "AS{ASN} {organization}"`（可选字段缺失时官方直接省略键，判存在不判 null，缺失保守取空）。**跨轮缓存**：查询结果落工作目录 `ip_cache.json`（`.gitignore` 忽略，Actions 经 cache 步骤跨轮恢复），键=IP、值=`{cc,proxy,hosting,isp,as,ts}`、TTL 24h——命中零外查，19k 次/天绝大部分是重复 IP，缓存把真实外查量压到最低；JSON 损坏自动当空缓存重建、写失败不致命。
- **关键参数**：`BATCH=100`（每批条数，FFraud 补查同为 100 条/批）、`MAX_WORKERS=5`（并发批数）、`RATE_MAX=45/min`（滑动窗口硬限速，超了自动排队而不是被封）、`RETRY=2`（真指数退避 1.5s/3s，最后一次失败不再空等一轮）、`FFRAUD_GAP=0.05s`（FFraud 单条间隔防 burst 429），ip-api 重试耗尽整批填 `err` 占位后交 FFraud 补查。
- **信号**：`countryCode` 判非中；`proxy`/`hosting` 是已知代理/机房标记（越少越干净）。输出统计 `non_cn`、`clean_non_cn`（非中 + 非代理 + 非机房 = 最干净）；geo 缺失占比写进 payload 的 `geo_missing_ratio`，**> 20% 打 `::warning::`**（三层链大概率整体失败，非中过滤会大面积失效——只 warning 不 exit，数据质量问题不让 workflow 变红）。
- **耗时**：与阶段 4 合计 ~10 s。

## 阶段 4：优选并写 KV — `top_select.py`

- **输入**：`purity.json` → **输出**：`top100_detail.json`、`top100_summary.json`，并写 KV `top100:nodes`。
- **做什么**：过滤出口非中（`geo` 已知且 `!= CN`）+ 可用性及格线（`delay <= DELAY_CAP`，**2000 ms**；协议测天然超时 5000，曾拍 800ms 会系统性误杀亚洲）→ 打分 → 取前 100。
- **打分**（只按纯净度）：`score = 纯净分 × 10`，纯净分 = `is_proxy is False` 与 `is_hosting is False` 各 1 分 → **0/10/20 三档**。**没有速度分**：机房测的延迟不参与排名（GitHub 机房离加拿大近，按它排会把榜单推向对国内不友好的地区），只在 `DELAY_CAP` 当及格线用；排序按 `-score` 稳定排序，**同档保持上游顺序**——无 `rtt` 次键，也不做 geo 偏好（链式下物理距离不代表节点质量，选点交给客户端 url-test 本机实测）。
- **KV 写入**：`PUT .../storage/kv/namespaces/<ns>/values/top100:nodes`，值是节点数组 JSON（`proto/server/port/ident/geo/raw` 六字段最小格式，`geo` 供 Worker 拼"地区-IP"节点名），失败退避重试 1 次。env：`CLOUDFLARE_API_TOKEN` / `CF_ACCOUNT_ID` / `CF_KV_NAMESPACE_ID` **三者齐全才写 KV**（账号与命名空间一律从 env 取，代码不内置兜底；缺任一只出 detail/summary 文件不写 KV）。
- **写 KV 前的闸门**（任一触发 → `::error::` + exit 1，KV 保留旧数据续命，detail/summary 照常落盘）：① 空数据门槛 `MIN_TOP = 30`；② 骤降保护——读 KV 现役 `top100:nodes` 长度当上轮 selected（summary 是运行产物不入库），跌幅 > 50% 拒写；③ `put_kv` 失败同样 error + exit 1，不再静默当成功。
- **档内密度配额**（纯度档排序之后、同档上游顺序之上贪心跳过）：同 `server` ≤ 3、同 `as` ≤ 8，防单一出口商/机房刷屏；踢除计数写进 summary 的 `quota_kicked`。不碰 geo、不碰 `DELAY_CAP` 边界。

## 阶段 5：触发 Worker 重建

**只写 `top100:nodes` 不触发重建的话，用户拿到的永远是上一次 rebuild 的旧配置**——订阅读的是 KV 缓存 `config:yaml`，必须显式触发：

```bash
URL="${WORKER_PUSH_URL%/}/rebuild"   # 去尾斜杠；WORKER_PUSH_URL 形如 https://<worker>/push/<令牌>
curl -X POST "$URL"
```

- secret 未配置 → `::error::` + exit 1（长期缺 secret 是部署错误：KV 更新永远进不了订阅）。
- 返回非 200 → `::error::` + exit 1（订阅仍是旧数据，借失败邮件暴露，不再 warning 静默过）。
- 响应示例：`{"ok":true,"msg":"已重建，top100 N 个","stats":{...}}`。

阶段 4 会另打印两行 geo 诊断：`入口1000 geo 前15`（含近华合计与 CN 数）和 `候选池 geo 前15`（定位亚洲节点是死在上游还是被及格线踢的）。

最后 `摘要` 步骤 `if: always()` 打印 `top100_summary.json`（`generated_at / input / non_cn / selected / geo 分布 / proto 分布 / kv_written`）。

## 耗时基线（Actions ubuntu-latest 实测）

| 步骤 | 耗时 | 关键手段 |
|---|---|---|
| 1 抓取 99 源 | ~1 min | keep-alive 连接复用、单源 10s 熔断、48 源并发 |
| 2a TCP 粗筛 43.7 万 | ~1.6 min | asyncio + pacer 节流 3000/s、端点去重回填 |
| 2b 协议初筛 5 万 | ~2.5 min | 8 实例并行 `-t` 预检、delay 超时 5s、512 并发、出口证书自证剔除假证书出口 |
| 3 + 4 纯净度与优选写 KV | ~10 s | ip-api 5 并发 + 45/min 限速 |
| **总计** | **~5.5 min** | 基线 20.5 min → 优化后约 5.45–5.5 min（约 3.8 倍） |

各阶段精确耗时每次运行会打印 `[诊断]` 行与阶段日志，以实际运行为准。

## 相关

- 整体架构、KV 键、链式代理见 [architecture.md](architecture.md)。
- 五段脚本之外，`probe_warp.py`（WARP 接入点实测）与 `cf_kv.py`（KV 读写 CLI）由 `pipeline.yml` 使用，见架构文档的 workflow 分工表。
