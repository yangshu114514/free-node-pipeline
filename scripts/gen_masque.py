#!/usr/bin/env python3
"""把 usque 的注册产物（config.json）转成 mihomo 订阅文件。

前置：先执行 `usque register` 拿到 config.json，本脚本只负责转换。
命令行：python3 gen_masque.py <usque-config.json> <输出目录>

两份产物是对外契约，文件名与正文格式不得变更：
    warp-masque.yaml              mihomo 全量配置
    warp-masque-shadowrocket.txt  Shadowrocket 的 masque:// 链接列表
"""
from __future__ import annotations

import json, os, sys
from dataclasses import dataclass
from urllib.parse import quote as url_quote

# ---- 接入点表（全部经真机握手实测筛过）----
# QUIC 有回包不代表隧道能建：162.159.194/196/197/204 段与 v6 的 102/105 段
# 会应答却 login 失败，已从表中剔除，勿凭 ping 结果往回加。
IPV4_POOLS = ("162.159.198.1", "162.159.198.2", "162.159.199.1", "162.159.199.2")
IPV6_POOLS = ("2606:4700:103::1", "2606:4700:103::2",
              "2606:4700:104::1", "2606:4700:104::2")
# 4443/8095 为后补测端口，4 地址 × 2 端口实测全通
LISTEN_PORTS = (443, 500, 1701, 4500, 4443, 8443, 8095)

# CF 没有 A 记录指向 MASQUE 段，官方域名只当 SNI 用，仍要落到一个 v4 地址上
SNI_HOST = "zt-masque.cloudflareclient.com"
SNI_TARGET = ("162.159.198.1", 443)

# 兜底节点名（手动选择组里的一员，也是 link 之外的第 57 个节点）
FALLBACK_LABEL = "WARP-官方域名"

RAW_MIRROR = "https://raw.githubusercontent.com"
# (策略组, 规则集地址)：classical 行为，正文 text 格式，每日拉新
RULE_PACKS = (
    ("🎯 全球直连", f"{RAW_MIRROR}/cmliu/ACL4SSR/refs/heads/main/Clash/CFnat.list"),
    ("🎯 全球直连", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list"),
    ("🎯 全球直连", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/UnBan.list"),
    ("🛑 全球拦截", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"),
    ("🍃 应用净化", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"),
    ("🍃 应用净化", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/adobe.list"),
    ("🍃 应用净化", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/IDM.list"),
    ("📢 谷歌FCM", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/GoogleFCM.list"),
    ("🎯 全球直连", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/GoogleCN.list"),
    ("🎯 全球直连", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/SteamCN.list"),
    ("Ⓜ️ 微软服务", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Microsoft.list"),
    ("🍎 苹果服务", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Apple.list"),
    ("📲 电报信息", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Telegram.list"),
    ("🤖 AI服务", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list"),
    ("🤖 AI服务", f"{RAW_MIRROR}/juewuy/ShellClash/master/rules/ai.list"),
    ("🤖 AI服务", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/Copilot.list"),
    ("🤖 AI服务", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/GithubCopilot.list"),
    ("🤖 AI服务", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/Claude.list"),
    ("🤖 AI服务", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/Gemini.list"),
    ("📹 油管视频", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/YouTube.list"),
    ("🎥 奈飞视频", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list"),
    ("🌍 国外媒体", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/ProxyMedia.list"),
    ("🌍 国外媒体", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/Emby.list"),
    ("🚀 节点选择", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/ProxyLite.list"),
    ("🚀 节点选择", f"{RAW_MIRROR}/cmliu/ACL4SSR/main/Clash/CMBlog.list"),
    ("🎯 全球直连", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"),
    ("🎯 全球直连", f"{RAW_MIRROR}/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list"),
)

# 规则集只覆盖 OpenAI / Claude / Gemini / Copilot，其余家没人维护，这批手写补上。
# 只收各家自有域名：googleapis.com、cloudflare.com 这类共用域名一旦进来，
# 会把大量无关流量拽进 AI 分组。须与 worker/src/config.js 里的同名表保持一致。
# 空格分隔、无引号无逗号——渲染时 split() 展开，保证与产物行形态彻底解耦。
AI_HOSTS = """
chatgpt.com openai.com oaistatic.com sora.com openai.fm operator.chatgpt.com chat.com anthropic.com
claude.ai claudeusercontent.com gemini.google.com aistudio.google.com
generativelanguage.googleapis.com notebooklm.google.com notebooklm.google labs.google
deepmind.com x.ai grok.com meta.ai
perplexity.ai pplx.ai perplexity.com mistral.ai
chat.mistral.ai cohere.com cohere.ai ai21.com
together.ai together.xyz fireworks.ai groq.com
huggingface.co hf.co huggingface.js.org replicate.com
replicate.delivery runpod.io modal.com openrouter.ai
poe.com quora.com cursor.com cursor.sh
codeium.com windsurf.com tabnine.com sourcegraph.com
phind.com v0.dev v0.app bolt.new
lovable.dev devin.ai cognition.ai midjourney.com
stability.ai stablediffusionweb.com leonardo.ai runwayml.com
pika.art lumalabs.ai ideogram.ai recraft.ai
krea.ai civitai.com elevenlabs.io eleven-labs.com
play.ht suno.com suno.ai udio.com
assemblyai.com deepgram.com you.com kagi.com
exa.ai tavily.com jasper.ai copy.ai
writesonic.com notion.so langchain.com langsmith.com
wandb.ai weightsandbiases.com pinecone.io weaviate.io
qdrant.tech chromadb.com deepseek.com moonshot.cn
moonshotai.com kimi.com bigmodel.cn zhipuai.cn
z.ai minimaxi.com minimax.io hailuoai.com
siliconflow.cn dashscope.aliyuncs.com
""".split()

# 产物文件名（workflow 与下游按这两个名字取件）
YAML_NAME = "warp-masque.yaml"
LINKS_NAME = "warp-masque-shadowrocket.txt"

# 产物尾部固定规则（顺序敏感：局域网免解析 → 中国直连 → 兜底）
TAIL_RULES = (
    "GEOIP,LAN,🎯 全球直连,no-resolve",
    "GEOIP,CN,🎯 全球直连",
    "MATCH,🐟 漏网之鱼",
)

# 单节点 masque 出站里不随账号变的字段（顺序即产物顺序）
PROXY_STATIC = (
    ("mtu", "1280"),
    ("udp", "true"),
    ("remote-dns-resolve", "true"),
    ("dns", "[1.1.1.1, 2606:4700:4700::1111]"),
)

# rule-providers 每条的公共字段（url/path 按条目另生成）
PROVIDER_STATIC = (
    ("type", "http"),
    ("behavior", "classical"),
    ("format", "text"),
    ("interval", "86400"),
)

# 产物头注释（节点数那行动态拼接）
BANNER = (
    "# Cloudflare WARP over MASQUE - mihomo 配置",
    "# 由 GitHub Actions 自动生成，请勿手工编辑",
    "# 需要 mihomo Alpha 分支：稳定版没有 masque outbound",
    "#",
)


@dataclass(frozen=True)
class AccessPoint:
    """一个 MASQUE 接入点；sni 只在走官方域名时非空，alias 覆盖自动命名。"""
    host: str
    port: int
    sni: str | None = None
    alias: str | None = None

    @property
    def is_v6(self) -> bool:
        return ":" in self.host

    @property
    def label(self) -> str:
        if self.alias:
            return self.alias
        if self.is_v6:
            seg, tail = self.host.split(":")[2], self.host.rsplit(":", 1)[-1]
            return f"WARP6-{seg}-{tail}-{self.port}"
        return f"WARP-{'.'.join(self.host.split('.')[2:])}-{self.port}"


def access_points() -> list[AccessPoint]:
    """全量接入点矩阵：8 地址 × 7 端口 + 1 个官方域名兜底。"""
    grid = [AccessPoint(host, port)
            for host in IPV4_POOLS + IPV6_POOLS
            for port in LISTEN_PORTS]
    grid.append(AccessPoint(SNI_TARGET[0], SNI_TARGET[1],
                            sni=SNI_HOST, alias=FALLBACK_LABEL))
    return grid


# ---- 以下为纯 YAML 行渲染器：数据表 → 文本，缩进规则只在这里 ----

def emit(pairs, depth: int = 0) -> list[str]:
    """(键, 值) 序列 → YAML 行。值分三型：标量串 / 元组-of-元组(嵌套) / 元组-of-串(列表)。"""
    rows, pad = [], " " * depth
    for key, val in pairs:
        if isinstance(val, str):
            rows.append(f"{pad}{key}: {val}")
        elif isinstance(val[0], tuple):
            rows.append(f"{pad}{key}:")
            rows += emit(val, depth + 2)
        else:
            rows.append(f"{pad}{key}:")
            rows += [f"{pad}  - {item}" for item in val]
    return rows


def bullets(items, depth: int) -> list[str]:
    pad = " " * depth
    return [f"{pad}  - {item}" for item in items]


# ---- 配置正文的固定段（数据形态，渲染后与产物逐字节一致）----

CORE_KV = (
    ("mixed-port", "7890"),
    ("allow-lan", "false"),
    ("mode", "rule"),
    ("log-level", "info"),
    ("ipv6", "true"),
    ("unified-delay", "true"),
    ("tcp-concurrent", "true"),
    ("find-process-mode", "'off'"),
    ("external-controller", "127.0.0.1:9090"),
)

PROFILE_KV = (
    ("profile", (
        ("store-selected", "true"),
        ("store-fake-ip", "true"),
    )),
)

SNIFFER_KV = (
    ("sniffer", (
        ("enable", "true"),
        ("sniff", (
            ("HTTP", (("ports", "[80, 8080-8880]"), ("override-destination", "true"))),
            ("TLS", (("ports", "[443, 8443]"),)),
            ("QUIC", (("ports", "[443, 8443]"),)),
        )),
        ("skip-domain", ("'+.push.apple.com'", "'+.apple.com'")),
    )),
)

DNS_KV = (
    ("dns", (
        ("enable", "true"),
        ("listen", "0.0.0.0:1053"),
        ("ipv6", "true"),
        ("enhanced-mode", "fake-ip"),
        ("fake-ip-range", "198.18.0.1/16"),
        ("fake-ip-filter", ("'+.lan'", "'+.local'",
                            "'*.msftconnecttest.com'", "'*.msftncsi.com'")),
        ("default-nameserver", ("223.5.5.5", "119.29.29.29")),
        ("nameserver", ("https://223.5.5.5/dns-query",
                        "https://1.12.12.12/dns-query")),
        ("proxy-server-nameserver", ("https://223.5.5.5/dns-query",)),
        ("nameserver-policy", (
            ("'geosite:cn,private'", ("https://223.5.5.5/dns-query",
                                      "https://1.12.12.12/dns-query")),
            ("'geosite:geolocation-!cn'", ("https://1.1.1.1/dns-query",
                                           "https://8.8.8.8/dns-query")),
        )),
    )),
)

# 16 个策略组：(名称, 类型, 附加字段, 成员)；成员为 ALL_NODES 表示列全部接入点
ALL_NODES = object()
PROBE_URL = "http://www.gstatic.com/generate_204"

GROUPS = (
    ("🚀 节点选择", "select", (), ("♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT")),
    ("☑️ 手动切换", "select", (), ALL_NODES),
    ("♻️ 自动选择", "url-test",
     (("url", PROBE_URL), ("interval", "300"), ("tolerance", "50"), ("lazy", "false")),
     ALL_NODES),
    ("🔄 故障转移", "fallback", (("url", PROBE_URL), ("interval", "180")), ALL_NODES),
    ("📹 油管视频", "select", (),
     ("🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT")),
    ("🎥 奈飞视频", "select", (),
     ("🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT")),
    ("🌍 国外媒体", "select", (),
     ("🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "🎯 全球直连")),
    ("📲 电报信息", "select", (), ("🚀 节点选择", "♻️ 自动选择", "🎯 全球直连")),
    ("🤖 AI服务", "select", (),
     ("🚀 节点选择", "♻️ 自动选择", "🔄 故障转移", "☑️ 手动切换", "DIRECT")),
    ("Ⓜ️ 微软服务", "select", (), ("🎯 全球直连", "🚀 节点选择", "♻️ 自动选择")),
    ("🍎 苹果服务", "select", (), ("🎯 全球直连", "🚀 节点选择", "♻️ 自动选择")),
    ("📢 谷歌FCM", "select", (), ("🚀 节点选择", "🎯 全球直连", "♻️ 自动选择")),
    ("🎯 全球直连", "select", (), ("DIRECT", "🚀 节点选择", "♻️ 自动选择")),
    ("🛑 全球拦截", "select", (), ("REJECT", "DIRECT")),
    ("🍃 应用净化", "select", (), ("REJECT", "DIRECT")),
    ("🐟 漏网之鱼", "select", (), ("🚀 节点选择", "🎯 全球直连", "♻️ 自动选择")),
)


def flatten_armor(pem: str) -> str:
    """剥 PEM 头尾与换行，只留 base64 本体（多行拼成一行）。"""
    kept = []
    for line in pem.strip().splitlines():
        body = line.strip()
        if body and not line.startswith("-----"):
            kept.append(body)
    return "".join(kept)


def normalize_private(raw: str) -> str:
    """私钥可能是 PEM 也可能是裸 base64，统一成裸值。"""
    val = raw.strip()
    return flatten_armor(val) if val.startswith("-----") else val


def render_proxy(point: AccessPoint, secret: str, public: str,
                 intranet_v4: str, intranet_v6: str) -> str:
    """单个 masque 出站的 YAML 片段。"""
    # 裸 IPv6 带冒号，YAML 里不加引号会被解析成映射
    server = f'"{point.host}"' if point.is_v6 else point.host
    head = [
        f"  - name: {point.label}",
        "    type: masque",
        f"    server: {server}",
        f"    port: {point.port}",
    ]
    if point.sni:
        head.append(f"    sni: {point.sni}")
    head += [
        f"    private-key: {secret}",
        f"    public-key: {public}",
        f"    ip: {intranet_v4}",
        f"    ipv6: {intranet_v6}",
        *[f"    {k}: {v}" for k, v in PROXY_STATIC],
    ]
    return "\n".join(head)


def render_group(name: str, gtype: str, opts, members, node_labels: list[str]) -> str:
    rows = [f"  - name: {name}", f"    type: {gtype}"]
    rows += [f"    {k}: {v}" for k, v in opts]
    rows.append("    proxies:")
    rows += bullets(node_labels if members is ALL_NODES else members, 4)
    return "\n".join(rows)


def pack_providers() -> tuple[str, list[str]]:
    """规则集定义 + 对应 RULE-SET 规则行，编号 rule00 起按表顺序。"""
    providers, rules = [], []
    for idx, (group, url) in enumerate(RULE_PACKS):
        tag = f"rule{idx:02d}"
        block = [f"  {tag}:"] + [f"    {k}: {v}" for k, v in PROVIDER_STATIC]
        block += [f"    url: {url}", f"    path: ./ruleset/{tag}.list"]
        providers.append("\n".join(block))
        rules.append(f"  - RULE-SET,{tag},{group}")
    return "\n".join(providers), rules


def encode_component(value: object) -> str:
    """Shadowrocket 查询参数编码：逗号保持字面量（dns 字段按逗号分隔解析）。"""
    return url_quote(str(value), safe="").replace("%2C", ",")


def shadowrocket_links(conf: dict, secret: str, public: str) -> list[str]:
    """masque:// 链接列表，字段与命名对齐 Shadowrocket 的 masque 实现：
    masque://<endpoint_ip>:<port>?publicKey=&privateKey=&ip=&dns=&udp=&cc=&flag=#<名称>
    publicKey 用剥壳后的 base64 DER，privateKey 沿用 usque 原值。"""
    head = "&".join([
        "publicKey=" + encode_component(public),
        "privateKey=" + encode_component(secret),
        "ip=" + encode_component(conf["ipv4"]),
        "dns=" + encode_component("1.1.1.1, 8.8.8.8"),
        "udp=1",
        "cc=" + encode_component(""),
        "flag=" + encode_component("CDN"),
    ])
    links = []
    for point in access_points():
        if point.sni:          # 官方域名只用于 SNI，链接里仍是 IP 直连
            continue
        host = f"[{point.host}]" if point.is_v6 else point.host
        links.append(f"masque://{host}:{point.port}?{head}#{encode_component(point.label)}")
    return links


def assemble(conf: dict) -> tuple[list[str], str, int]:
    """主装配：返回 (masque链接, yaml 正文, 节点数)。输入输出契约与历史版本一致。"""
    secret = normalize_private(conf["private_key"])
    public = flatten_armor(conf["endpoint_pub_key"])
    intranet_v4, intranet_v6 = conf["ipv4"], conf["ipv6"]

    points = access_points()
    labels = [p.label for p in points]
    proxies = [render_proxy(p, secret, public, intranet_v4, intranet_v6) for p in points]

    providers, pack_rules = pack_providers()
    # 内联 AI 域名排在 RULE-SET 之前，避免被上游更宽的条目抢先命中
    host_rules = [f"  - DOMAIN-SUFFIX,{d},🤖 AI服务" for d in AI_HOSTS]
    rules = "\n".join(host_rules + pack_rules)
    group_blocks = [render_group(*spec, labels) for spec in GROUPS]
    links = shadowrocket_links(conf, secret, public)

    doc = [
        *BANNER,
        f"# 节点 {len(labels)} 个，endpoint 均经真机握手实测。",
        "# private-key 等同账号凭据。",
        "",
        *emit(CORE_KV),
        "",
        *emit(PROFILE_KV),
        "",
        *emit(SNIFFER_KV),
        "",
        *emit(DNS_KV),
        "",
        "proxies:",
        "\n".join(proxies),
        "",
        "proxy-groups:",
        "\n\n".join(group_blocks),
        "",
        "rule-providers:",
        providers,
        "",
        "rules:",
        rules,
        *bullets(TAIL_RULES, 0),
        "",
    ]
    return links, "\n".join(doc), len(labels)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("用法：gen_masque.py <usque-config.json> <输出目录>", file=sys.stderr)
        return 1
    src, outdir = argv[1], argv[2]
    with open(src, encoding="utf-8") as fh:
        conf = json.load(fh)

    os.makedirs(outdir, exist_ok=True)
    links, body, count = assemble(conf)

    yaml_path = os.path.join(outdir, YAML_NAME)
    with open(yaml_path, "w", encoding="utf-8") as fh:
        fh.write(body)

    link_path = os.path.join(outdir, LINKS_NAME)
    with open(link_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(links) + "\n")

    print(f"已生成 {yaml_path}")
    print(f"已生成 {link_path}（{len(links)} 条 masque:// 链接）")
    print(f"节点数 {count}")
    print(f"内网地址 {conf['ipv4']} / {conf['ipv6']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
