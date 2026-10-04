// 生成 mihomo 配置：WARP MASQUE 直连（兜底）+ top100 精选源。
// 接入点清单是真机握手实测筛过的，别往回加 162.159.194/196/197/204
// 和 v6 的 102/105 段 —— 它们回 QUIC 包但 login 失败。
//
// 分流极简版：代理组只有 6 个 —— WARP直连 / top100 / 🚀 节点选择 /
// 🤖 AI服务 / 🎥 奈飞视频 / 🐟 漏网之鱼；规则只分四类（AI、奈飞、
// 局域网+中国、MATCH 兜底），其余（广告、微软、苹果、电报、油管、FCM、
// Steam 之类）全部砍掉 —— 用不到的规则集只会拖慢 mihomo 启动。
//
// 出口矩阵：4 个 v4 + 4 个 v6 接入地址，全量配同一组端口；
// 4443 / 8095 是补测追加的 —— v4 地址挨个握一手，这两口 8/8 全通。
const V4 = [
  "162.159.198.1",
  "162.159.198.2",
  "162.159.199.1",
  "162.159.199.2",
];
const V6 = [
  "2606:4700:103::1",
  "2606:4700:103::2",
  "2606:4700:104::1",
  "2606:4700:104::2",
];
const PORTS = [
  443, 500, 1701, 4500,
  4443, 8443, 8095,
];

// CF 没有 A 记录指向 MASQUE 段，官方域名只能用在 SNI 上
const OFFICIAL_SNI = "zt-masque.cloudflareclient.com";
const SNI_NODE = ["162.159.198.1", 443];

// 规则集清单统一挂在这个 raw 主机后面，拼路径即成下载地址
const RAW_HOST = "https://raw.githubusercontent.com";
// 规则集只留四类：AI、奈飞、局域网+中国（走 DIRECT，功能性必需）。
// 广告净化 / 微软 / 苹果 / 电报 / 油管 / FCM / Steam 等全删 ——
// 下载一堆用不到的规则集只会拖慢 mihomo 启动。
const RULESETS = [
  // 1) AI → 🤖 AI服务
  { group: "🤖 AI服务", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list" },
  { group: "🤖 AI服务", url: RAW_HOST + "/juewuy/ShellClash/master/rules/ai.list" },
  { group: "🤖 AI服务", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/Copilot.list" },
  { group: "🤖 AI服务", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/GithubCopilot.list" },
  { group: "🤖 AI服务", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/Claude.list" },
  { group: "🤖 AI服务", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/Gemini.list" },
  // 2) 奈飞 → 🎥 奈飞视频
  { group: "🎥 奈飞视频", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list" },
  // 3) 局域网 + 中国域名 → DIRECT
  // 路径坑：这三条在 ACL4SSR 仓库的 Clash/ 根目录，Clash/Ruleset/ 下没有
  // （写成 Ruleset/ 会拿到 page_not_found，国内分流整段失效）
  { group: "DIRECT", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list" },
  { group: "DIRECT", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list" },
  { group: "DIRECT", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list" },
];

// 接入点条目名：IPv4 取末两段 "198.1-443"，
// IPv6 取网段与接口号 "v6-103-1-443"（首两段是固定前缀，没有区分度）
function endpointLabel(addr, port) {
  if (addr.includes(":")) {
    const zone = addr.split(":");
    return ["v6", zone[2], zone.at(-1), port].join("-");
  }
  return `${addr.split(".").slice(2).join(".")}-${port}`;
}

/** 单个接入点的 YAML 块。产物行序是契约，源码按两行一组折叠书写。 */
function masqueBlock(name, addr, port, priv, pub, v4, v6, sni) {
  // 裸 IPv6 含冒号，不加引号 YAML 会当成映射
  const srv = addr.includes(":") ? `"${addr}"` : addr;
  const sniLine = sni ? `\n    sni: ${sni}` : "";
  return [
    `  - name: ${name}`, `    type: masque`,
    `    server: ${srv}`, `    port: ${port}${sniLine}`,
    `    private-key: ${priv}`, `    public-key: ${pub}`,
    `    ip: ${v4}`, `    ipv6: ${v6}`,
    `    mtu: 1280`, `    udp: true`,
    `    remote-dns-resolve: true`,
    // 隧道内 DNS 也走 DoH：明文 UDP 53 本来只在 CF 隧道里可见，叠一层 TLS
    // 后连 CF 内网那一段也是密文。dns.ParseNameServer 接受完整 DNS 语法，
    // 查询经 ipStackNetDialer 从 TUN 口发出，即"在隧道内查"。
    // IPv6 字面量必须带方括号，否则 URL 解析失败。
    `    dns: ['https://1.1.1.1/dns-query', 'https://[2606:4700:4700::1111]/dns-query']`,
  ].join("\n");
}

// 「官方域名」是恒在的兜底接入点，条目名全局唯一
const OFFICIAL_NAME = "官方域名";

/** 全量接入点清单：8 个地址 × 7 个端口 + 官方域名兜底。 */
function fullCatalog() {
  const list = [...V4, ...V6].flatMap((addr) =>
    PORTS.map((port) => ({ name: endpointLabel(addr, port), ip: addr, port, sni: null })));
  list.push({ name: OFFICIAL_NAME, ip: SNI_NODE[0], port: SNI_NODE[1], sni: OFFICIAL_SNI });
  return list;
}

/** 实测精选筛选：picked 与真实命中都得 ≥4 条才生效（防半残数据把
 *  接入点砍到不可用），官方域名兜底恒在列。不满足返回 null 走全量。 */
function measuredSubset(catalog, picked) {
  if (!Array.isArray(picked) || picked.length < 4) return null;
  const index = new Map(catalog.map((e) => [e.name, e]));
  const hits = picked.map((n) => index.get(n)).filter(Boolean);
  if (hits.length < 4) return null;
  if (!hits.some((e) => e.name === OFFICIAL_NAME)) hits.push(index.get(OFFICIAL_NAME));
  return hits;
}

/** 生成 MASQUE 接入点，一次遍历装配两份清单：
 *  entries —— WARP直连 组的成员名；
 *  proxies —— 对应的 YAML 正文块。
 *  endp 为 warp:endpoints 实测结果时按 picked 精选，否则全量 57 个。 */
function assembleEndpoints(warp, endp) {
  const { privateKey: priv, peerPublicKey: pub, ipv4: v4, ipv6: v6 } = warp;
  const catalog = fullCatalog();
  const chosen = measuredSubset(catalog, endp?.picked) ?? catalog;

  const bag = { entries: [], proxies: [] };
  for (const ep of chosen) {
    bag.entries.push(ep.name);
    bag.proxies.push(masqueBlock(ep.name, ep.ip, ep.port, priv, pub, v4, v6, ep.sni));
  }
  return bag;
}

// 内联 AI 域名源清单 —— 规则集只覆盖了 OpenAI / Claude / Gemini / Copilot
// 四家的一部分，其余靠这里逐条补上，走 DOMAIN-SUFFIX 精确匹配。
//
// 填充红线：只收各家自己的域名。共用域（googleapis.com、cloudflare.com、
// stripe.com 这类）一律不进 —— 上游 ai.list 就把整个 googleapis.com 和
// bing.com 都标成了 AI，结果一大坨无关流量被拽进 AI 分组。
// 下面按厂商标注分组只是源码组织，渲染时拍平成一维清单，顺序即产物顺序。
const AI_RULE_HOSTS = [
  { house: "OpenAI 补充", doms: [
    // 主域与静态资源域必须内联：RULE-SET(OpenAi.list) 是运行时 24h 一拉的
    // 外部文件，下载失败/重下窗口内裸 chatgpt.com 会漏到 GEOIP,CN 段，
    // CDN IP 被判 CN 即国内直连 → TLS 被 RST → 浏览器 ERR_SSL_PROTOCOL_ERROR
    //（线上偶发"隐私设置错误"实锤根因）。内联写死在 yaml 里永不失效。
    "chatgpt.com", "openai.com", "oaistatic.com", "sora.com",
    "openai.fm", "operator.chatgpt.com", "chat.com",
  ] },
  { house: "Anthropic", doms: [
    "anthropic.com",
    "claude.ai",
    "claudeusercontent.com",
  ] },
  { house: "Google 系", doms: [
    "gemini.google.com",
    "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "notebooklm.google.com",
    "notebooklm.google",
    "labs.google",
    "deepmind.com",
  ] },
  { house: "xAI", doms: ["x.ai", "grok.com"] },
  { house: "Meta", doms: ["meta.ai"] },
  { house: "Perplexity", doms: [
    "perplexity.ai",
    "pplx.ai",
    "perplexity.com",
  ] },
  { house: "Mistral", doms: ["mistral.ai", "chat.mistral.ai"] },
  { house: "Cohere / AI21 / Together / Fireworks / Groq", doms: [
    "cohere.com",
    "cohere.ai",
    "ai21.com",
    "together.ai",
    "together.xyz",
    "fireworks.ai",
    "groq.com",
  ] },
  { house: "开源社区与推理平台", doms: [
    "huggingface.co",
    "hf.co",
    "huggingface.js.org",
    "replicate.com",
    "replicate.delivery",
    "runpod.io",
    "modal.com",
    "openrouter.ai",
    "poe.com",
    "quora.com",
  ] },
  { house: "编程助手", doms: [
    "cursor.com",
    "cursor.sh",
    "codeium.com",
    "windsurf.com",
    "tabnine.com",
    "sourcegraph.com",
    "phind.com",
    "v0.dev",
    "v0.app",
    "bolt.new",
    "lovable.dev",
    "devin.ai",
    "cognition.ai",
  ] },
  { house: "图像与视频", doms: [
    "midjourney.com",
    "stability.ai",
    "stablediffusionweb.com",
    "leonardo.ai",
    "runwayml.com",
    "pika.art",
    "lumalabs.ai",
    "ideogram.ai",
    "recraft.ai",
    "krea.ai",
    "civitai.com",
  ] },
  { house: "语音", doms: [
    "elevenlabs.io",
    "eleven-labs.com",
    "play.ht",
    "suno.com",
    "suno.ai",
    "udio.com",
    "assemblyai.com",
    "deepgram.com",
  ] },
  { house: "搜索与写作", doms: [
    "you.com",
    "kagi.com",
    "exa.ai",
    "tavily.com",
    "jasper.ai",
    "copy.ai",
    "writesonic.com",
    "notion.so",
  ] },
  { house: "观测与工具链", doms: [
    "langchain.com",
    "langsmith.com",
    "wandb.ai",
    "weightsandbiases.com",
    "pinecone.io",
    "weaviate.io",
    "qdrant.tech",
    "chromadb.com",
  ] },
  // 国产这批默认也走代理：很多服务出了境反而连不上，或者要境外手机号
  { house: "国产", doms: [
    "deepseek.com",
    "moonshot.cn",
    "moonshotai.com",
    "kimi.com",
    "bigmodel.cn",
    "zhipuai.cn",
    "z.ai",
    "minimaxi.com",
    "minimax.io",
    "hailuoai.com",
    "siliconflow.cn",
    "dashscope.aliyuncs.com",
  ] },
];
const AI_FLAT = AI_RULE_HOSTS.flatMap((seg) => seg.doms);

/** 组成员清单行：统一走 JSON 引号转义 —— 成员名里混进引号/换行也不会
 *  把 YAML 结构撕开（注入面在节点名与组名，这里必须引住）。 */
const listRows = (a, n = 6) =>
  a.map((x) => " ".repeat(n) + `- ${JSON.stringify(String(x))}`).join("\n");

/** rule-providers 与 rules 两段正文。
 *  provider 统一编号 ruleNN（NN = 清单下标，左补零），路径随之确定；
 *  内联 AI 域名排在全部 RULE-SET 之前，否则会被上游规则集里
 *  更宽的条目抢先命中。 */
function buildRules() {
  const indexed = RULESETS.map(({ group, url }, seq) => ({
    id: `rule${String(seq).padStart(2, "0")}`,
    group,
    url,
  }));

  const providers = indexed
    .map(({ id, url }) =>
      `  ${id}:\n    type: http\n    behavior: classical\n    format: text\n` +
      `    interval: 86400\n    url: ${url}\n    path: ./ruleset/${id}.list`)
    .join("\n");

  const matched = indexed.map(({ id, group }) => `  - RULE-SET,${id},${group}`);
  const inline = AI_FLAT.map((d) => `  - DOMAIN-SUFFIX,${d},🤖 AI服务`);

  return { prov: providers, rules: [...inline, ...matched].join("\n") };
}

/** 公共头部：端口 / 模式 / sniffer / dns 四段拼成的 YAML 正文。
 *  产物行序是契约，源码按行组折叠（每源码行承载多个产物行）。 */
function commonHeader(flag) {
  const basics = [
    "mixed-port: 7890", "allow-lan: false", "mode: rule", "log-level: info",
    `ipv6: ${flag}`, "unified-delay: true", "tcp-concurrent: true",
    "find-process-mode: 'off'", "external-controller: 127.0.0.1:9090", "",
  ];
  const profile = [
    "profile:", "  store-selected: true", "  store-fake-ip: true", "",
  ];
  const sniff = [
    "sniffer:", "  enable: true", "  sniff:",
    "    HTTP:", "      ports: [80, 8080-8880]", "      override-destination: true",
    "    TLS:", "      ports: [443, 8443]",
    "    QUIC:", "      ports: [443, 8443]",
    "  skip-domain:", "    - '+.push.apple.com'", "    - '+.apple.com'", "",
  ];
  // 全链路加密 DNS，零明文 UDP 53：
  //   境内域名 → 阿里云 DoH，直连查（最快，且境内域名本就不该出境）
  //   境外域名 → Cloudflare DoH，经 WARP 加密隧道查
  // 为什么境外这条必须走代理：1.1.1.1:443 在国内直连会被 RST 掐断；就算连上，
  // 明文结果也会被污染，污染成 CN IP 后会被 GEOIP,CN 判成直连 → TLS 被切。
  // 为什么可以走代理而不死循环：DNS 查询本身是一次 TCP 连接，走 WARP直连 组；
  // 该组的健康检查目标（gstatic）由 masque 出站自己的 remote-dns-resolve 在
  // 隧道内解析，不回到这里的 nameserver-policy，环在这里断开。
  const resolver = [
    "dns:", "  enable: true", "  listen: 0.0.0.0:1053",
    `  ipv6: ${flag}`, "  enhanced-mode: fake-ip", "  fake-ip-range: 198.18.0.1/16",
    "  fake-ip-filter:",
    "    - '+.lan'", "    - '+.local'",
    "    - '*.msftconnecttest.com'", "    - '*.msftncsi.com'",
    // bootstrap：只用来解析下面这些 DoH 服务器自己的域名，必须写纯 IP。
    // 文档允许此处为加密 DNS，于是明文 UDP 53 在这份配置里彻底消失。
    "  default-nameserver:",
    "    - https://223.5.5.5/dns-query", "    - https://1.12.12.12/dns-query",
    "  nameserver:",
    "    - https://223.5.5.5/dns-query", "    - https://1.12.12.12/dns-query",
    // 代理节点域名解析：只能境内直连，否则解析节点域名本身又要先连上节点
    "  proxy-server-nameserver:",
    "    - https://223.5.5.5/dns-query",
    "  nameserver-policy:",
    "    'geosite:cn,private':",
    "      - https://223.5.5.5/dns-query", "      - https://1.12.12.12/dns-query",
    // `#组名` 后缀 = 这条 DNS 查询走哪个出口，mihomo 官方语法
    "    'geosite:geolocation-!cn':",
    "      - 'https://1.1.1.1/dns-query#WARP直连'",
    "      - 'https://1.0.0.1/dns-query#WARP直连'",
  ];
  return [...basics, ...profile, ...sniff, ...resolver].join("\n");
}

/** 下游分组：极简 6 组 —— WARP直连 / top100（有数据才生成）/ 🚀 节点选择 /
 *  🤖 AI服务 / 🎥 奈飞视频 / 🐟 漏网之鱼。
 *  picks 是 🚀 节点选择 的成员（= 底座，空 top100 时只有 WARP直连）；
 *  aiPicks 是 AI/奈飞 的成员（top100 优先，兜底 WARP直连，最后总开关）；
 *  catchPicks 是漏网之鱼（总开关优先，兜底殿后）。
 *  所有成员只允许指向存在的组/节点 —— 不留悬空引用。 */
function buildGroups(entries, topNames, picks, aiPicks, catchPicks) {
  const blocks = [];
  blocks.push([
    `  - name: WARP直连`, `    type: url-test`,
    // https + expected-status 204：明文 http 测试会被劫持干扰（mihomo 官方 warning 点名），
    // 严格状态码校验让坏接入点立刻判负；timeout 收紧、失败 3 次即强制重测（快踢）。
    // 测速 URL 用 gstatic 204（1.1.1.1 返回 200，配 204 校验会全组判死）。
    `    url: https://www.gstatic.com/generate_204`, `    interval: 300`,
    `    expected-status: 204`, `    timeout: 5000`, `    max-failed-times: 3`,
    `    tolerance: 50`, `    lazy: true`, `    proxies:`,
    listRows(entries),
  ].join("\n"));
  // 空 top100 时整组不生成，picks/aiPicks/catchPicks 里也不能出现 top100
  // tolerance 100：链式双层抖动大，比最快慢 100ms 内不切换，避免切换风暴掐断长连接
  // interval 180：100 节点每 3 分钟一轮即可，一分钟一轮是客户端 40 倍负担
  if (topNames.length) {
    blocks.push([
      `  - name: top100`, `    type: url-test`,
      // 同 WARP 组：https+204 严格校验+快超时+失败 3 次强制重测——MASQUE 底座
      // UDP 抖动时坏节点快速判负踢出，别让浏览器拿着断了的连接报 SSL 错。
      `    url: https://www.gstatic.com/generate_204`, `    interval: 180`,
      `    expected-status: 204`, `    timeout: 5000`, `    max-failed-times: 3`,
      `    tolerance: 100`, `    lazy: true`, `    proxies:`,
      listRows(topNames),
    ].join("\n"));
  }
  const menu = (label, members) =>
    [`  - name: ${label}`, `    type: select`, `    proxies:`, listRows(members)].join("\n");
  blocks.push(menu("🚀 节点选择", picks));
  blocks.push(menu("🤖 AI服务", aiPicks));
  blocks.push(menu("🎥 奈飞视频", aiPicks));
  blocks.push(menu("🐟 漏网之鱼", catchPicks));
  return blocks.join("\n\n");
}

// ---- top100 精选源：{"proto","server","port","ident"} → mihomo proxies ----
//
// 下面这批正则/单例提到模块级：每次 rebuild 对约 100 个节点各调一遍这些
// 辅助函数，写在函数体内的正则字面量每次调用都要重新求值构造对象，
// TextDecoder 同理。模块级只构造一次，全部调用复用。

const RE_B64_DASH = /-/g;          // base64url → base64：- → +
const RE_B64_SLASH = /_/g;         // base64url → base64：_ → /
const RE_DIGITS = /^\d+$/;         // port 必须纯数字（"443/" 这类混进来的直接丢）
const RE_NONPRINT = /[^\x20-\x7e]/; // 非可打印 ASCII：区分 base64 "method:pass" 与明文
const RE_PLUS = /\+/g;             // query 解码前把 + 还原成空格
const RE_COLON = /:/g;             // IPv6 server 名里的冒号 → 点（节点名用）
const RE_HTTPS = /^https:/i;        // http 出站的 raw 是否 https（决定 tls）
const RE_CTRL = /[\x00-\x1f\x7f-\x9f]/g; // 控制字符 C0+C1+DEL 全剥：节点名等（防换行撕 YAML）
// （线上实锤：某免费节点 alpn 字段带 U+0096 混入订阅，mihomo 宽容、Verge 严格解析器
//   直接拒载 "invalid yaml"——C1 区间 \x80-\x9f 必须一起盖住）
const RE_CTRL_SCALAR = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g;
// j() 专用：保留 \t\n\r（JSON.stringify 会把它们安全转义成字面 \n 等，标量合法），
// 其余控制字符剥掉——既堵 U+0096 类脏字节，又不破坏"换行被转义进标量"的注入语义
const b64TextDec = new TextDecoder(); // b64d 共享单例，避免每次解码新建

// 能生成 proxy 的 proto 白名单：不支持的 proto 早退，
// 省掉 rawParams 解析 + base 字符串拼接（最终同样落 default 返回 null）
const PROTO_OK = new Set([
  "vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "http", "socks", "socks5",
]);

const b64c = (s) => String(s).replace(RE_B64_DASH, "+").replace(RE_B64_SLASH, "/");

/** 把 base64 解成 utf8 文本；不是合法 base64 就原样返回。 */
function b64d(s) {
  try {
    const bin = atob(b64c(String(s)));
    // 逐字节写入（等价旧的 Uint8Array.from + 回调，少一层函数调用开销）
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return b64TextDec.decode(bytes);
  } catch {
    return String(s ?? "");
  }
}

/** YAML 标量统一加双引号，内部转义，别让密码里的特殊字符搞坏整份配置。 */
// YAML 标量统一出口：先剥 C0/C1 控制字符（保留 \t\n\r，见 RE_CTRL_SCALAR）再转义——
// 控制字符对 yaml 值无正当用途，JSON.stringify 对 \x80-\x9f 原样放行会让严格解析器拒载
const j = (s) => JSON.stringify(String(s ?? "").replace(RE_CTRL_SCALAR, ""));

/** 从 ident 里解析 user:pass（http/socks 的用户凭证）。 */
function splitIdent(ident) {
  const s = String(ident ?? "");
  const i = s.lastIndexOf(":");
  if (i > 0 && i < s.length - 1) return { user: s.slice(0, i), pass: s.slice(i + 1) };
  return null;
}

/** 完整 URI 的 userinfo（`proto://user:pass@host`）。
 *  raw 是协议测的实测口径、逐字完整；ident 字段在流水线侧可能被截断，
 *  凡 raw 带认证一律以 raw 为准，ident 只做无 raw 时的兜底。 */
function authFromRaw(raw) {
  const m = /^[A-Za-z0-9+.-]+:\/\/([^@/?#]*)@/.exec(raw);
  if (!m || !m[1]) return null;
  let info = m[1];
  try { info = decodeURIComponent(info); } catch { /* 保留原样 */ }
  const cut = info.lastIndexOf(":");
  if (cut <= 0 || cut === info.length - 1) return { user: "", pass: info };
  return { user: info.slice(0, cut), pass: info.slice(cut + 1) };
}

/** ss:// 的认证段，兼容三种形态：
 *   1) ss://BASE64(method:pass)@host:port
 *   2) ss://method:pass@host:port（明文）
 *   3) ss://BASE64(method:pass@host:port)（整体编码）
 *  解不出返回 null，回落 ident 解析。 */
function ssAuthFromRaw(raw) {
  if (!/^ss:\/\//i.test(raw)) return null;
  const body = raw.slice(5).split(/[?#]/)[0];
  let info;
  if (body.includes("@")) {
    info = body.slice(0, body.lastIndexOf("@"));
  } else {
    const whole = b64d(body);
    const at = whole.lastIndexOf("@");
    info = at > 0 ? whole.slice(0, at) : whole;
  }
  const dec = b64d(info);            // 形态 1；非法 base64 时 b64d 原样返回
  const text = RE_NONPRINT.test(dec) ? info : dec;
  // 按**第一个**冒号切：method 永不含冒号，而 password 可以含冒号 ——
  // AEAD-2022 是双向各一把 PSK，形态就是 method:key1:key2（如
  // 2022-blake3-aes-256-gcm:<client>:<server>）。用 lastIndexOf 会把
  // 前两段整体当 method → 内核 unknown method 拒载整份配置（2026-10-04 实测事故）。
  const cut = text.indexOf(":");
  if (cut <= 0 || cut === text.length - 1) return null;
  return { method: text.slice(0, cut), pass: text.slice(cut + 1) };
}

/** 节点名：地区-IP（如 JP-42.51.25.69）。geo 缺失兜底 XX；
 *  同名冲突（同 IP 多端口/协议、IPv6 截断撞车）依次追加 :端口、#序号保证唯一。
 *  host 先剥控制字符 —— KV 数据不设防，换行混进名字会撕开成员清单行。 */
function topName(geo, server, port, used) {
  const host = String(server ?? "").replace(RE_COLON, ".").replace(RE_CTRL, "");
  const short = host.length > 20 ? host.slice(0, 20) : host || "unknown";
  const cc = /^[A-Z]{2}$/.test(String(geo || "")) ? geo : "XX";
  let name = `${cc}-${short}`;
  if (used.has(name)) name = `${name}:${port}`;
  let k = 2;
  while (used.has(name)) name = `${cc}-${short}:${port}#${k++}`;
  used.add(name);
  return name;
}

/** 解析 URI query 参数（vless/trojan/hy2 等 ?a=b&c=d），返回小写 key 字典。 */
function rawQuery(raw) {
  const qi = raw.indexOf("?");
  if (qi < 0) return {};
  let qs = raw.slice(qi + 1);
  const hi = qs.indexOf("#");
  if (hi >= 0) qs = qs.slice(0, hi);
  const out = {};
  for (const pair of qs.split("&")) {
    if (!pair) continue;
    const ei = pair.indexOf("=");
    const k = (ei < 0 ? pair : pair.slice(0, ei)).toLowerCase();
    let v = ei < 0 ? "" : pair.slice(ei + 1);
    try { v = decodeURIComponent(v.replace(RE_PLUS, " ")); } catch { /* 保留原值 */ }
    out[k] = v;
  }
  return out;
}

/** 从 raw 完整 URI 还原关键传输参数（sni/tls/network/path/host/flow/alpn/fp/reality），
 *  让节点配置与原 URI 一致 —— 缺这些参数握手必失败（之前全 Timeout 的根因）。
 *  vmess 的参数在 base64 json 内，单独解。无 raw 时返回 {}（回退默认）。 */
function rawParams(raw) {
  if (!raw) return {};
  // indexOf + slice 替代 split("://")：split 会分配整个数组，这里只要前缀。
  // 语义与 split 逐字一致：无 "://" 时取整串，有则取第一段。
  const sep = raw.indexOf("://");
  const proto = (sep < 0 ? raw : raw.slice(0, sep)).toLowerCase();
  if (proto === "vmess") {
    try {
      const jm = JSON.parse(b64d(raw.slice("vmess://".length)) || "{}");
      return {
        tls: jm.tls === "tls" || jm.tls === "reality",
        reality: jm.tls === "reality",
        sni: jm.sni || jm.host || "",
        network: String(jm.net || "tcp").toLowerCase(),
        path: jm.path || "", host: jm.host || "",
        alpn: "", flow: "", fp: "chrome", pbk: "", sid: "",
        vmessId: jm.id || "", alterId: Number(jm.aid) || 0,
      };
    } catch { return {}; }
  }
  const q = rawQuery(raw);
  const sec = (q.security || "").toLowerCase();
  const proto2 = proto;
  return {
    tls: sec === "tls" || sec === "reality" || sec === "tls1.3" || proto2 === "trojan",
    reality: sec === "reality",
    sni: q.sni || q.peer || q.servername || "",
    network: String(q.type || "tcp").toLowerCase(),
    path: q.path || "",
    host: q.host || "",
    alpn: q.alpn || "",
    flow: q.flow || "",
    fp: q.fp || "chrome",
    pbk: q.pbk || "", sid: q.sid || "",
  };
}

/** 单条 top100 节点转 mihomo proxy YAML；没法映射的返回 null 跳过。
 *  优先从 n.raw（完整 URI）还原全部传输参数；无 raw 时按四字段默认补齐。
 *  proto 由 buildConfig 循环算好传入（原来每个节点在这里重复算一次），
 *  已做过 toLowerCase+trim；白名单外的直接返回 null——与旧代码落到
 *  switch default 的结果一致，只是省掉后面的解析与拼接。 */
function topProxy(n, name, proto) {
  if (!PROTO_OK.has(proto)) return null;
  const server = String(n?.server ?? "").trim();
  // KV 里混过 "443/"（URI host:port/path 没拆净）——不清洗会让 mihomo
  // strconv.Atoi 炸掉整份配置（proxy 100: cannot parse 'port' 全设备拒载）。
  // indexOf 切尾比 split("/")[0] 少一次数组分配，结果逐字一致。
  let port = String(n?.port ?? "").trim();
  const slash = port.indexOf("/");
  if (slash >= 0) port = port.slice(0, slash).trim();
  if (!server || !port || !RE_DIGITS.test(port)) return null;
  const ident = String(n?.ident ?? "").trim();
  const raw = String(n?.raw ?? "").trim();
  const p = rawParams(raw);
  const ind = "    ";
  const base = `  - name: ${j(name)}\n${ind}type: ${proto}\n` +
               `${ind}server: ${j(server)}\n${ind}port: ${j(port)}`;

  // 网络层（按 raw 的 type 还原 ws/grpc/http）
  const nw = p.network || "tcp";
  let net = "";
  if (nw === "ws") {
    net += `\n${ind}network: ws\n${ind}ws-opts:\n${ind}${ind}path: ${j(p.path || "/")}`;
    if (p.host) net += `\n${ind}${ind}headers:\n${ind}${ind}${ind}Host: ${j(p.host)}`;
  } else if (nw === "grpc") {
    net += `\n${ind}network: grpc\n${ind}grpc-opts:\n${ind}${ind}grpc-service-name: ${j(p.path || "")}`;
  } else if (nw === "http" || nw === "h2") {
    net += `\n${ind}network: http\n${ind}http-opts:\n${ind}${ind}path: ${j(p.path || "/")}`;
    if (p.host) net += `\n${ind}${ind}headers:\n${ind}${ind}${ind}Host: ${j(p.host)}`;
  }
  // TLS / Reality 层
  let tls = "";
  if (p.reality) {
    tls = `\n${ind}tls: true\n${ind}servername: ${j(p.sni || server)}` +
          `\n${ind}reality-opts:\n${ind}${ind}public-key: ${j(p.pbk)}` +
          (p.sid ? `\n${ind}${ind}short-id: ${j(p.sid)}` : "");
  } else if (p.tls) {
    tls = `\n${ind}tls: true\n${ind}servername: ${j(p.sni || server)}` +
          `\n${ind}skip-cert-verify: true`;
  }
  const fp = `\n${ind}client-fingerprint: ${j(p.fp || "chrome")}`;
  const alpn = p.alpn ? `\n${ind}alpn: [${p.alpn.split(",").map((a) => j(a.trim())).join(", ")}]` : "";

  switch (proto) {
    case "vless": {
      if (!ident) return null;
      const flow = p.flow ? `\n${ind}flow: ${j(p.flow)}` : "";
      return `${base}\n${ind}uuid: ${j(ident)}${flow}${tls}${net}${fp}${alpn}`;
    }
    case "vmess": {
      let id = p.vmessId || ident;
      let alterId = p.alterId || 0;
      if (!p.vmessId && ident.startsWith("{")) {
        try {
          const d = JSON.parse(ident);
          if (d.add && String(d.add) !== server) return null;
          id = String(d.id ?? "");
          alterId = Number(d.aid) || 0;
        } catch { /* 按明文 uuid */ }
      }
      if (!id) return null;
      return `${base}\n${ind}uuid: ${j(id)}\n${ind}alterId: ${alterId}` +
             `\n${ind}cipher: auto\n${ind}udp: true${tls}${net}${fp}`;
    }
    case "trojan": {
      // 密码优先取 raw 的 userinfo（实测完整口径），ident 只兜底
      const pass = authFromRaw(raw)?.pass || ident;
      if (!pass) return null;
      const t = tls || `\n${ind}tls: true\n${ind}servername: ${j(p.sni || server)}` +
                       `\n${ind}skip-cert-verify: true`;
      return `${base}\n${ind}password: ${j(pass)}${t}${net}${fp}${alpn}`;
    }
    case "ss": {
      if (!ident) return null;
      let method = "aes-256-gcm", password = ident;
      const via = ssAuthFromRaw(raw);   // raw 完整口径优先，ident 只兜底
      if (via) {
        method = via.method; password = via.pass;
      } else {
        // 只解一次码：判定条件（非空 + 全可打印 ASCII）与解码结果原样内联
        const dec = b64d(ident);
        if (dec.length > 0 && !RE_NONPRINT.test(dec)) {
          const mp = dec.split(":");
          // 同 ssAuthFromRaw：按第一个冒号切，password 保留剩余全部段
          // （AEAD-2022 的 method:key1:key2 形态，尾冒号切会撑爆 method）
          if (mp.length >= 2) { method = mp[0]; password = mp.slice(1).join(":"); }
        } else {
          const parts = ident.split(":");
          if (parts.length >= 3) { method = parts[0]; password = parts.slice(1).join(":"); }
          else if (parts.length === 2 && parts[0].includes("-")) { method = parts[0]; password = parts[1]; }
        }
      }
      if (!password) return null;
      return `${base}\n${ind}cipher: ${j(method)}\n${ind}password: ${j(password)}` +
             `${net}\n${ind}udp: true`;
    }
    case "hysteria2":
    case "hy2": {
      if (!ident) return null;
      return `${base.replace(`type: ${proto}`, "type: hysteria2")}` +
             `\n${ind}password: ${j(ident)}` +
             (p.tls || p.sni ? `\n${ind}sni: ${j(p.sni || server)}` : "") +
             `\n${ind}skip-cert-verify: true`;
    }
    case "http": {
      // 认证优先 raw（完整口径）；raw 无认证才回落 ident 的 user:pass 拆分
      const via = authFromRaw(raw);
      const up = via?.user ? via : splitIdent(ident);
      let s = base;
      if (up?.user) s += `\n${ind}username: ${j(up.user)}\n${ind}password: ${j(up.pass)}`;
      else if (via?.pass || ident) s += `\n${ind}password: ${j(via?.pass || ident)}`;
      // TLS 取决于传输（raw 是否 https://），与有无认证无关——用 ident 判断是错的
      return `${s}\n${ind}tls: ${(p.tls || RE_HTTPS.test(raw)) ? "true" : "false"}`;
    }
    case "socks":
    case "socks5": {
      const via = authFromRaw(raw);
      const up = via?.user ? via : splitIdent(ident);
      let s = base.replace(`type: ${proto}`, "type: socks5");
      if (up?.user) s += `\n${ind}username: ${j(up.user)}\n${ind}password: ${j(up.pass)}`;
      else if (via?.pass || ident) s += `\n${ind}password: ${j(via?.pass || ident)}`;
      return `${s}\n${ind}udp: true`;
    }
    default:
      return null;
  }
}

/** 正文时间戳行的读取与剥离 —— 供调用方比较"内容（不含时间戳）是否变化"，
 *  实现数据没变就不刷新时间戳、ETag 保持稳定。 */
export const stampOf = (yaml) =>
  /# 由 Cloudflare Worker 生成于 ([^\n]+)/.exec(yaml)?.[1] || null;
export const withoutStamp = (yaml) =>
  yaml.replace(/# 由 Cloudflare Worker 生成于 [^\n]+/, "# 由 Cloudflare Worker 生成于 @");

export function buildConfig(warp, warpEp, top100Nodes, dataStamp) {
  const { entries, proxies } = assembleEndpoints(warp, warpEp);

  // top100 → proxies。KV 读不到时传 []，优雅降级成只有 WARP 兜底
  const topNames = [];
  const topProxies = [];
  const usedNames = new Set();
  (Array.isArray(top100Nodes) ? top100Nodes : []).forEach((n, i) => {
    // proto 每节点只算一次：topName 不再用 proto（名字=地区-IP），
    // topProxy 沿用 trim 后口径（与其旧内部口径一致）
    const proto0 = String(n?.proto || "?").toLowerCase();
    const name = topName(n?.geo, n?.server, n?.port, usedNames);
    const y = topProxy(n, name, proto0.trim());
    if (y) {
      topNames.push(name);
      // 链式中转：top100 出站先走 WARP直连组，把"国内→节点"的被墙段换成
      // "WARP出口→节点"海外直连段。本机三轮实测：直连 1/100 稳定，链式 44/100 稳定。
      // 必须指 WARP直连 而不能指 ♻️自动选择——自动选择的成员含 top100 自身，
      // url-test 把它选中时 dialer→组→top100→dialer 形成环，mihomo 直接拒连甚至崩内核。
      topProxies.push(`${y}\n    dialer-proxy: "WARP直连"`);
    }
  });

  const picks = ["WARP直连"];
  if (topNames.length) picks.push("top100");
  // AI/奈飞：top100 优先，WARP 兜底，最后总开关（空 top100 时整个不引用它）
  const aiPicks = topNames.length
    ? ["top100", "WARP直连", "🚀 节点选择"]
    : ["WARP直连", "🚀 节点选择"];
  // 漏网之鱼：总开关优先，底座殿后
  const catchPicks = topNames.length
    ? ["🚀 节点选择", "top100", "WARP直连"]
    : ["🚀 节点选择", "WARP直连"];

  const { prov, rules } = buildRules();

  const groups = buildGroups(entries, topNames, picks, aiPicks, catchPicks);
  // 时间戳由调用方给（数据时间），缺省才用当前时刻——数据不变 → 时间戳不变
  const stamp = dataStamp || new Date().toISOString();
  const head = `# WARP MASQUE 直连 + top100 精选
# 由 Cloudflare Worker 生成于 ${stamp}
#
#   WARP直连   本机 -> MASQUE -> 目标（出口是 CF 自己的 IP，兜底保底）
#   top100     top100 精选源${topNames.length ? `（${topNames.length} 个，url-test 自动挑最快）` : "（KV 暂无数据，仅保留 WARP）"}
#
# 分流只有四类，按序：
#   1) AI 域名     -> 🤖 AI服务
#   2) 奈飞        -> 🎥 奈飞视频
#   3) 局域网+中国 -> DIRECT
#   4) 其余全部    -> 🐟 漏网之鱼（MATCH 兜底）
#
# 接入点 ${entries.length} 个${topNames.length ? ` + top100 节点 ${topNames.length} 个` : ""}，
# 任一环失效都有替代路径。
#
# 需要 mihomo Alpha 分支：稳定版没有 masque outbound。
# private-key 等同 WARP 账号凭据，别外传。

${commonHeader(true)}

proxies:
${[...proxies, ...topProxies].join("\n")}

proxy-groups:
${groups}
`;
  // 规则区单独拼，正文字节序与模板直写逐字一致
  const tail = [
    "", "rule-providers:", prov, "", "rules:", rules,
    "  - GEOIP,LAN,DIRECT,no-resolve",
    "  - GEOIP,CN,DIRECT",
    "  - MATCH,🐟 漏网之鱼",
    "",
  ].join("\n");

  const yaml = head + tail;

  return {
    yaml,
    entries: entries.length,
    warpEndpoints: entries.length,
    top100: topNames.length,
  };
}
