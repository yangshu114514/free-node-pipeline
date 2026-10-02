# 加密 DNS：境内走阿里云 DoH，境外走 Cloudflare DoH（经 WARP 隧道）

> 本文既说明本仓库两份订阅产物里的 DNS 是怎么配的，也给出**把它套用到任意另一份
> mihomo/Clash 订阅**的完整步骤与检查清单。

## 一、最终效果

| 查询对象 | 用哪个 DNS | 从哪里发出 | 为什么这样选 |
|---|---|---|---|
| 境内域名 | 阿里云 DoH `https://223.5.5.5/dns-query`（备：腾讯 `https://1.12.12.12/dns-query`） | **直连** | 境内域名本就该境内解析，直连最快 |
| 境外域名 | Cloudflare DoH `https://1.1.1.1/dns-query`、`https://1.0.0.1/dns-query` | **经 `WARP直连` 组（加密隧道）** | 直连 1.1.1.1:443 在国内会被 RST；就算连上，结果也会被污染 |
| 代理节点自己的域名 | 阿里云 DoH | 直连 | 解析节点域名不能先连上节点（鸡生蛋） |
| 上面那些 DoH 服务器自己的域名 | 阿里/腾讯 DoH（bootstrap） | 直连 | `default-nameserver` 只能写纯 IP |
| MASQUE 隧道内部的解析 | Cloudflare DoH | 隧道内 | 端到端不留明文 |

一句话：**这份配置里不存在任何明文 DNS 流量**，而且境外域名拿到的解析结果不被污染。

## 二、改了什么（对照）

### 1) 客户端 DNS 段

```yaml
# 改前
  default-nameserver:
    - 223.5.5.5            # ← 明文 UDP 53
    - 119.29.29.29         # ← 明文 UDP 53
  nameserver:
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  proxy-server-nameserver:
    - https://223.5.5.5/dns-query
  nameserver-policy:
    'geosite:cn,private':
      - https://223.5.5.5/dns-query
      - https://1.12.12.12/dns-query
    'geosite:geolocation-!cn':
      - https://1.1.1.1/dns-query     # ← 加密了，但在国内直连会被 RST
      - https://8.8.8.8/dns-query
```

```yaml
# 改后
  default-nameserver:                 # bootstrap：只用于解析下面这些 DoH 自己的域名
    - https://223.5.5.5/dns-query     # 官方文档明确：这里"必须为 IP，可为加密 DNS"
    - https://1.12.12.12/dns-query
  nameserver:                         # 默认解析器 = 境内加密 DNS
    - https://223.5.5.5/dns-query
    - https://1.12.12.12/dns-query
  proxy-server-nameserver:            # 节点域名解析：必须境内直连
    - https://223.5.5.5/dns-query
  nameserver-policy:
    'geosite:cn,private':             # 境内 → 阿里云 DoH，直连
      - https://223.5.5.5/dns-query
      - https://1.12.12.12/dns-query
    'geosite:geolocation-!cn':        # 境外 → Cloudflare DoH，出口钉死 WARP 出口组
      - 'https://1.1.1.1/dns-query#WARP直连'
      - 'https://1.0.0.1/dns-query#WARP直连'
```

> 上面 `#` 后面写的是 **Worker 动态订阅**里的组名 `WARP直连`。
> **手动线订阅**（`scripts/gen_masque.py` 的产物）里没有这个组，它的 WARP
> url-test 组原名就是 `♻️ 自动选择`，所以那边的值是
> `'https://1.1.1.1/dns-query#♻️ 自动选择'`。两处组名都是**沿用各产物原有
> 组名，没有为了 DNS 去改名**。

### 2) MASQUE 出站的隧道内 DNS

```yaml
# 改前：隧道内明文 UDP 53
    remote-dns-resolve: true
    dns: [1.1.1.1, 2606:4700:4700::1111]

# 改后：隧道内 DoH
    remote-dns-resolve: true
    dns: ['https://1.1.1.1/dns-query', 'https://[2606:4700:4700::1111]/dns-query']
```

> IPv6 字面量**必须带方括号**，否则 URL 解析失败。
> 这两条 DNS 由 mihomo 的 `dns.ParseNameServer()` 解析（接受完整 DNS 语法），
> 查询经 `ipStackNetDialer` 从 TUN 口发出 —— 也就是"在隧道里查"。

### 3) Shadowrocket 链接的 `dns=` 参数

```
# 改前
dns=1.1.1.1, 8.8.8.8
# 改后（URL 编码后，逗号保留字面量）
dns=https%3A%2F%2F1.1.1.1%2Fdns-query,https%3A%2F%2F1.0.0.1%2Fdns-query
```

Shadowrocket 官方支持 DoH/DoT/DoQ。若某个版本不认 URI 里的 DoH 写法，
回退成 `1.1.1.1, 1.0.0.1` 即可 —— 安全性只降到"隧道内明文"，**不会泄漏到公网**。

## 三、三个必须理解的机制

### 1. `default-nameserver` = "解析 DNS 服务器域名的 DNS"

它存在的唯一理由是打破鸡生蛋：`nameserver` 里如果写了域名形式的 DoH
（如 `https://doh.pub/dns-query`），这个域名本身需要先被解析。所以
`default-nameserver` 只能是**纯 IP**（域名会被拒），而"加密 DNS"是允许的
—— 写成 `https://223.5.5.5/dns-query` 就是 IP 形式的 DoH，自己不需要被解析。

**这就是明文 UDP 53 的唯一可能藏身处**。把它也换成 DoH，明文就彻底消失了。

### 2. `#组名` 后缀 = 这条 DNS 查询走哪个出口

mihomo 的 DNS 服务器条目支持用 `#` 附加参数：

```yaml
  nameserver:
    - 'https://1.1.1.1/dns-query#WARP直连'   # 经 WARP直连 组查
    - 'https://8.8.8.8/dns-query#DIRECT'     # 强制直连
```

`#RULES` 是特殊值，表示"遵守路由规则"（等价于 `respect-rules: true`）。
**组名必须与订阅里真实存在的组名逐字一致**（含 emoji 和空格），写错了
mihomo 会把它当接口名处理或直接报错。

### 3. 为什么指定 `WARP直连` 不会死循环

会踩的坑是这样想的："DNS 走 WARP 组 → WARP 组要做健康检查 → 健康检查要
解析测速域名 → 又要查 DNS → 循环"。

实际不会，因为 **MASQUE 出站配了 `remote-dns-resolve` + `dns` 时，mihomo
用该出站自己的 resolver，且经 `ipStackNetDialer` 从隧道口发出**：

```go
// mihomo adapter/outbound/masque.go
if option.RemoteDnsResolve && len(option.Dns) > 0 {
    nss, _ := dns.ParseNameServer(option.Dns)
    for i := range nss { nss[i].ProxyAdapter = outbound }
    outbound.resolver = dns.NewResolver(dns.Config{Main: nss, IPv6: has6})
}
// DialContext 里：
options = append(options, dialer.WithResolver(r))
options = append(options, dialer.WithNetDialer(ipStackNetDialer{stack: w.tunDevice}))
```

也就是说：**`WARP直连` 组的健康检查目标（gstatic）是在隧道内用 1.1.1.1 解析的，
根本不回到客户端的 `nameserver-policy`** —— 环在这里就断了。

> 反过来，如果你的订阅里代理节点**没有** `remote-dns-resolve`，
> 那么给 DNS 指定代理组就有真实的循环风险。此时应改成 `#RULES`
> 并确保测速域名有一条直连解析策略。

## 四、套用到另一份订阅：步骤

### 第 0 步：确认订阅里有哪些组

```bash
grep -n "^  - name:" your-subscription.yaml
```

找出那个**恒定走 WARP/境外节点、且用户改不动**的 url-test 组名。
本仓库里：Worker 动态订阅叫 `WARP直连`；手动线订阅（`gen_masque.py` 产物）叫 `♻️ 自动选择`。
**`#` 后面的名字必须与你订阅里的组名逐字一致**（含 emoji 与空格），写错了
mihomo 会当成接口名处理或直接报错。

### 第 1 步：替换 `dns:` 整段

直接照抄「二、1)」的改后版本。要改的只有两处：

- `#WARP直连` → 你订阅里的组名（没有就删掉 `#...`，退化为直连，见第六节）
- 阿里云/腾讯的 DoH 地址按需替换（`https://dns.alidns.com/dns-query` 是阿里的域名形式，
  但它需要 bootstrap 解析，**放在 `default-nameserver` 里会失败**，那里只能用 IP 形式）

### 第 2 步：节点里的隧道内 DNS

如果节点是 `type: masque` / `wireguard` 且带 `remote-dns-resolve: true`，
把 `dns:` 换成 DoH 数组（IPv6 记得方括号）。

### 第 3 步：校验

```bash
mihomo -t -d <工作目录> -f your-subscription.yaml
# 期望：configuration file ... test is successful
```

`-t` 会真实加载 geosite/geoip 数据并解析 `nameserver-policy`，
所以它能抓出组名拼错、IPv6 缺方括号、geosite 缺失等问题。

### 第 4 步：运行时确认（可选但推荐）

```bash
# 看 DNS 模块启动日志：会逐条打印 geosite 规则加载结果
mihomo -d <工作目录> -f your-subscription.yaml
# 期望看到：
#   Finished initial GeoSite rule cn => dns.nameserver-policy, records: 111274
#   Finished initial GeoSite rule geolocation-!cn => dns.nameserver-policy, records: 27206
```

records 为 0 或报 `list cn not found` 说明 geosite 数据坏了（见第六节）。

## 五、检查清单

- [ ] `default-nameserver` 下没有任何裸 IP（`- 223.5.5.5` 这种）
- [ ] `nameserver` / `proxy-server-nameserver` 全部是 `https://`
- [ ] `geosite:cn,private` 分支**没有** `#出口` 后缀（境内必须直连）
- [ ] `geosite:geolocation-!cn` 分支**有** `#WARP直连`（或你订阅里的等价组名）
- [ ] `#` 后面的组名与 `proxy-groups` 里的名字逐字一致
- [ ] masque 节点的 `dns:` 是 DoH，IPv6 带方括号
- [ ] `mihomo -t` 通过
- [ ] 日志里 geosite `cn` 与 `geolocation-!cn` 的 records 都远大于 0

## 六、前提与已知边界

1. **geosite 数据必须可用**。`geosite:cn,private` / `geosite:geolocation-!cn`
   这两条分流完全依赖 geosite 数据；数据缺失时 mihomo 会**直接拒绝加载配置**
   （不是降级）。本地实测：干净目录 + 下载失败 → `test failed`。
   所以客户端要保持 geodata 可更新（Clash Verge / mihomo 首次运行会下载）。
   若你的网络下不到 GitHub release，可加镜像：

   ```yaml
   geox-url:
     geosite: "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
     geoip:   "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
     mmdb:    "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb"
   ```

2. **境外 DNS 走代理的代价**：首次查询要等一次 TLS 握手（之后连接复用）。
   WARP 隧道内访问 1.1.1.1 是 CF 自家网络，延迟很低，实际感知不明显。

3. **代理组全挂时会怎样**：境外域名解析失败，但**不影响走代理的域名访问**
   —— fake-ip 模式下 mihomo 把域名交给代理远端解析，本地 DNS 只用于
   GEOIP 判断。失败会退化为 MATCH 兜底，不会断网。

4. **为什么境外统一用 Cloudflare 而不是 Google**：需求就是 Cloudflare；
   且 `1.1.1.1` / `1.0.0.1` 都在 CF 网络内，与 WARP 出口同网，路径最短。
   想加 `https://8.8.8.8/dns-query#WARP直连` 作为第三备也行。

5. **DNS 段的 `listen: 0.0.0.0:1053`** 是给局域网设备用的。若不需要
   别人用你的 DNS，改成 `127.0.0.1:1053` 更安全（本仓库保留原样）。

## 七、对应代码位置

| 产物 | 生成源 | DNS 段位置 |
|---|---|---|
| Worker 动态订阅 | `worker/src/config.js` | `commonHeader()` 的 `resolver` 数组 + `masqueBlock()` |
| 手动线订阅 / Shadowrocket | `scripts/gen_masque.py` | `DNS_KV` + `PROXY_STATIC` + `shadowrocket_links()` |

改完 Worker 侧要重新构建产物并过自检：

```bash
npx esbuild worker/src/index.js --bundle --format=esm --target=es2022 --outfile=worker/dist/worker.js
node make-worker.mjs          # 13 项关键特征自检（含加密 DNS 3 项 + 明文回魂 2 项）
node worker/test/config.test.mjs   # 79 项配置回归
python -m unittest discover -s tests -t .   # 39 项流水线测试
```

## 八、部署与线上生效（2026-10-02 实操记录）

改完 Worker 代码后，**换脚本 ≠ 订阅立即生效**，还差两步：

1. **上传新脚本**。线上 `omk-opera-masque` 是 **Service Worker 形态**
   （尾部 `self.addEventListener('fetch', ...)`，IIFE 包裹），上传时
   metadata 走 `body_part: "script"`；若误按 module 形态（`main_module`）
   传进去，`export default { fetch }` 缺失，**整个订阅站会挂**。
   账号是 `yangshugmail@gmail.com`（`cf --profile sub`），上传即自动部署
   100% 流量。

2. **触发重建**。订阅正文是 Worker 生成后**缓存进 KV**（`config:yaml`）
   的，脚本更新后旧正文仍会一直被返回，必须主动重建：

   ```bash
   # 令牌在 KV 键 proton:token（64 位），只在内存里用，不要打印
   curl -X POST "https://wtfyangshu.cc.cd/push/<令牌>/rebuild"
   # 期望: {"ok":true,"msg":"已重建，top100 100 个",...}
   ```

   另两个重建入口：`POST /api/refresh`（需管理员登录会话）、
   `POST /api/reset-warp`（同时重置 WARP 注册信息）。

**回滚点**：出问题时把流量切回旧版本即可，无需重新上传：

```bash
cf workers deployments create --worker omk-opera-masque --profile sub \
  --versions '[{"version_id":"3f8e2c9a-50b4-4c43-bfc2-26775dda6c45","percentage":100}]'
```

（`3f8e2c9a` 是本次部署前的版本；下次部署前先用
`cf workers deployments list --worker omk-opera-masque --profile sub`
记下当时的最新 `version_id` 作为新回滚点。）

**上线验收**（三道，缺一不可）：

```bash
# 1) 线上正文特征：阿里 DoH 在、#WARP直连 在、119.29 已灭、明文 dns:[1.1.1.1] 已灭
# 2) 本地 mihomo 校验线上正文（需要同目录有 GeoSite.dat/GeoIP.dat/Country.mmdb）
C:\ProgramData\clash-verge-service\cores\verge-mihomo-alpha.exe -t -d <目录> -f live-sub.yaml
#    期望: configuration file ... test is successful
# 3) 日志里两条 policy 的 records 数正常（cn 111274 / geolocation-!cn 27206）
```
