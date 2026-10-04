// worker/src/warp.js
var GATEWAY = "https://api.cloudflareclient.com/v0a4471";
var HEADERS = {
  "User-Agent": "WARP for Android",
  "CF-Client-Version": "a-6.35-4471",
  "Content-Type": "application/json; charset=UTF-8"
};
var toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
function randomB64(n) {
  return toBase64(crypto.getRandomValues(new Uint8Array(n)));
}
function randomHex(n) {
  const raw = crypto.getRandomValues(new Uint8Array(n));
  let out = "";
  for (const byte of raw) out += byte.toString(16).padStart(2, "0");
  return out;
}
function gatewayClock() {
  return (/* @__PURE__ */ new Date()).toISOString().replace("Z", "+00:00");
}
function warpUsable(cached) {
  const need = ["privateKey", "peerPublicKey", "ipv4", "ipv6"];
  return !!cached && need.every((f) => !!cached[f]);
}
async function enrollWarpDevice(deviceName = "cf-worker") {
  const enroll = await fetch(`${GATEWAY}/reg`, {
    method: "POST",
    headers: HEADERS,
    body: JSON.stringify({
      key: randomB64(32),
      install_id: "",
      fcm_token: "",
      tos: gatewayClock(),
      model: "PC",
      serial_number: randomHex(8),
      os_version: "",
      key_type: "curve25519",
      tunnel_type: "wireguard",
      locale: "en-US"
    })
  });
  if (!enroll.ok) {
    const detail = (await enroll.text()).slice(0, 200);
    throw new Error(`WARP \u5F00\u6237\u5931\u8D25 ${enroll.status}: ${detail}`);
  }
  const card = await enroll.json();
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"]
  );
  const publicSpki = toBase64(await crypto.subtle.exportKey("spki", pair.publicKey));
  const privatePkcs8 = toBase64(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  const privateSec1 = sec1FromPkcs8(privatePkcs8);
  const upgrade = await fetch(`${GATEWAY}/reg/${card.id}`, {
    method: "PATCH",
    headers: { ...HEADERS, Authorization: `Bearer ${card.token}` },
    body: JSON.stringify({
      key: publicSpki,
      key_type: "secp256r1",
      tunnel_type: "masque",
      name: deviceName
    })
  });
  if (!upgrade.ok) {
    const detail = (await upgrade.text()).slice(0, 200);
    throw new Error(`MASQUE \u6302\u8F7D\u5931\u8D25 ${upgrade.status}: ${detail}`);
  }
  const tuned = await upgrade.json();
  const wrapped = tuned.config?.peers?.[0]?.public_key || "";
  const barePeer = wrapped.includes("-----") ? wrapped.split("\n").filter((line) => line && !line.startsWith("-----")).join("") : wrapped;
  return {
    deviceId: card.id,
    token: card.token,
    privateKey: privateSec1,
    peerPublicKey: barePeer,
    ipv4: tuned.config?.interface?.addresses?.v4 || card.config?.interface?.addresses?.v4,
    ipv6: tuned.config?.interface?.addresses?.v6 || card.config?.interface?.addresses?.v6,
    registeredAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
function readTlv(bytes, at) {
  const tag = bytes[at];
  let size = bytes[at + 1];
  let body = at + 2;
  if (size & 128) {
    const wide = size & 127;
    size = 0;
    for (let k = 0; k < wide; k++) size = size << 8 | bytes[body + k];
    body += wide;
  }
  return [tag, body, size, body + size];
}
function encodeLength(n) {
  if (n < 128) return [n];
  if (n < 256) return [129, n];
  return [130, n >> 8, n & 255];
}
function sec1FromPkcs8(base64Pkcs8) {
  const der = Uint8Array.from(atob(base64Pkcs8), (ch) => ch.charCodeAt(0));
  let cursor = readTlv(der, 0)[1];
  cursor = readTlv(der, cursor)[3];
  cursor = readTlv(der, cursor)[3];
  const [outerTag, outerStart, outerLen] = readTlv(der, cursor);
  if (outerTag !== 4) throw new Error("PKCS8 \u7ED3\u6784\u4E0D\u7B26\u5408\u9884\u671F");
  const shell = der.subarray(outerStart, outerStart + outerLen);
  let walk = readTlv(shell, 0)[1];
  walk = readTlv(shell, walk)[3];
  const [keyTag, keyStart, keyLen] = readTlv(shell, walk);
  if (keyTag !== 4) throw new Error("SEC1 \u7ED3\u6784\u4E0D\u7B26\u5408\u9884\u671F");
  const secret = shell.subarray(keyStart, keyStart + keyLen);
  const CURVE_OID = [6, 8, 42, 134, 72, 206, 61, 3, 1, 7];
  const payload = [
    2,
    1,
    1,
    // version = 1
    4,
    secret.length,
    ...secret,
    // 私钥本体
    160,
    CURVE_OID.length,
    ...CURVE_OID
    // [0] namedCurve
  ];
  const frame = [48, ...encodeLength(payload.length), ...payload];
  return btoa(String.fromCharCode(...frame));
}

// worker/src/config.js
var V4 = [
  "162.159.198.1",
  "162.159.198.2",
  "162.159.199.1",
  "162.159.199.2"
];
var V6 = [
  "2606:4700:103::1",
  "2606:4700:103::2",
  "2606:4700:104::1",
  "2606:4700:104::2"
];
var PORTS = [
  443,
  500,
  1701,
  4500,
  4443,
  8443,
  8095
];
var OFFICIAL_SNI = "zt-masque.cloudflareclient.com";
var SNI_NODE = ["162.159.198.1", 443];
var RAW_HOST = "https://raw.githubusercontent.com";
var RULESETS = [
  // 1) AI → 🤖 AI服务
  { group: "\u{1F916} AI\u670D\u52A1", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/Ruleset/OpenAi.list" },
  { group: "\u{1F916} AI\u670D\u52A1", url: RAW_HOST + "/juewuy/ShellClash/master/rules/ai.list" },
  { group: "\u{1F916} AI\u670D\u52A1", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/Copilot.list" },
  { group: "\u{1F916} AI\u670D\u52A1", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/GithubCopilot.list" },
  { group: "\u{1F916} AI\u670D\u52A1", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/Claude.list" },
  { group: "\u{1F916} AI\u670D\u52A1", url: RAW_HOST + "/cmliu/ACL4SSR/main/Clash/Gemini.list" },
  // 2) 奈飞 → 🎥 奈飞视频
  { group: "\u{1F3A5} \u5948\u98DE\u89C6\u9891", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/Ruleset/Netflix.list" },
  // 3) 局域网 + 中国域名 → DIRECT
  // 路径坑：这三条在 ACL4SSR 仓库的 Clash/ 根目录，Clash/Ruleset/ 下没有
  // （写成 Ruleset/ 会拿到 page_not_found，国内分流整段失效）
  { group: "DIRECT", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list" },
  { group: "DIRECT", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list" },
  { group: "DIRECT", url: RAW_HOST + "/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list" }
];
function endpointLabel(addr, port) {
  if (addr.includes(":")) {
    const zone = addr.split(":");
    return ["v6", zone[2], zone.at(-1), port].join("-");
  }
  return `${addr.split(".").slice(2).join(".")}-${port}`;
}
function masqueBlock(name, addr, port, priv, pub, v4, v6, sni) {
  const srv = addr.includes(":") ? `"${addr}"` : addr;
  const sniLine = sni ? `
    sni: ${sni}` : "";
  return [
    `  - name: ${name}`,
    `    type: masque`,
    `    server: ${srv}`,
    `    port: ${port}${sniLine}`,
    `    private-key: ${priv}`,
    `    public-key: ${pub}`,
    `    ip: ${v4}`,
    `    ipv6: ${v6}`,
    `    mtu: 1280`,
    `    udp: true`,
    `    remote-dns-resolve: true`,
    // 隧道内 DNS 也走 DoH：明文 UDP 53 本来只在 CF 隧道里可见，叠一层 TLS
    // 后连 CF 内网那一段也是密文。dns.ParseNameServer 接受完整 DNS 语法，
    // 查询经 ipStackNetDialer 从 TUN 口发出，即"在隧道内查"。
    // IPv6 字面量必须带方括号，否则 URL 解析失败。
    `    dns: ['https://1.1.1.1/dns-query', 'https://[2606:4700:4700::1111]/dns-query']`
  ].join("\n");
}
var OFFICIAL_NAME = "\u5B98\u65B9\u57DF\u540D";
function fullCatalog() {
  const list = [...V4, ...V6].flatMap((addr) => PORTS.map((port) => ({ name: endpointLabel(addr, port), ip: addr, port, sni: null })));
  list.push({ name: OFFICIAL_NAME, ip: SNI_NODE[0], port: SNI_NODE[1], sni: OFFICIAL_SNI });
  return list;
}
function measuredSubset(catalog, picked) {
  if (!Array.isArray(picked) || picked.length < 4) return null;
  const index = new Map(catalog.map((e) => [e.name, e]));
  const hits = picked.map((n) => index.get(n)).filter(Boolean);
  if (hits.length < 4) return null;
  if (!hits.some((e) => e.name === OFFICIAL_NAME)) hits.push(index.get(OFFICIAL_NAME));
  return hits;
}
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
var AI_RULE_HOSTS = [
  { house: "OpenAI \u8865\u5145", doms: [
    // 主域与静态资源域必须内联：RULE-SET(OpenAi.list) 是运行时 24h 一拉的
    // 外部文件，下载失败/重下窗口内裸 chatgpt.com 会漏到 GEOIP,CN 段，
    // CDN IP 被判 CN 即国内直连 → TLS 被 RST → 浏览器 ERR_SSL_PROTOCOL_ERROR
    //（线上偶发"隐私设置错误"实锤根因）。内联写死在 yaml 里永不失效。
    "chatgpt.com",
    "openai.com",
    "oaistatic.com",
    "sora.com",
    "openai.fm",
    "operator.chatgpt.com",
    "chat.com"
  ] },
  { house: "Anthropic", doms: [
    "anthropic.com",
    "claude.ai",
    "claudeusercontent.com"
  ] },
  { house: "Google \u7CFB", doms: [
    "gemini.google.com",
    "aistudio.google.com",
    "generativelanguage.googleapis.com",
    "notebooklm.google.com",
    "notebooklm.google",
    "labs.google",
    "deepmind.com"
  ] },
  { house: "xAI", doms: ["x.ai", "grok.com"] },
  { house: "Meta", doms: ["meta.ai"] },
  { house: "Perplexity", doms: [
    "perplexity.ai",
    "pplx.ai",
    "perplexity.com"
  ] },
  { house: "Mistral", doms: ["mistral.ai", "chat.mistral.ai"] },
  { house: "Cohere / AI21 / Together / Fireworks / Groq", doms: [
    "cohere.com",
    "cohere.ai",
    "ai21.com",
    "together.ai",
    "together.xyz",
    "fireworks.ai",
    "groq.com"
  ] },
  { house: "\u5F00\u6E90\u793E\u533A\u4E0E\u63A8\u7406\u5E73\u53F0", doms: [
    "huggingface.co",
    "hf.co",
    "huggingface.js.org",
    "replicate.com",
    "replicate.delivery",
    "runpod.io",
    "modal.com",
    "openrouter.ai",
    "poe.com",
    "quora.com"
  ] },
  { house: "\u7F16\u7A0B\u52A9\u624B", doms: [
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
    "cognition.ai"
  ] },
  { house: "\u56FE\u50CF\u4E0E\u89C6\u9891", doms: [
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
    "civitai.com"
  ] },
  { house: "\u8BED\u97F3", doms: [
    "elevenlabs.io",
    "eleven-labs.com",
    "play.ht",
    "suno.com",
    "suno.ai",
    "udio.com",
    "assemblyai.com",
    "deepgram.com"
  ] },
  { house: "\u641C\u7D22\u4E0E\u5199\u4F5C", doms: [
    "you.com",
    "kagi.com",
    "exa.ai",
    "tavily.com",
    "jasper.ai",
    "copy.ai",
    "writesonic.com",
    "notion.so"
  ] },
  { house: "\u89C2\u6D4B\u4E0E\u5DE5\u5177\u94FE", doms: [
    "langchain.com",
    "langsmith.com",
    "wandb.ai",
    "weightsandbiases.com",
    "pinecone.io",
    "weaviate.io",
    "qdrant.tech",
    "chromadb.com"
  ] },
  // 国产这批默认也走代理：很多服务出了境反而连不上，或者要境外手机号
  { house: "\u56FD\u4EA7", doms: [
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
    "dashscope.aliyuncs.com"
  ] }
];
var AI_FLAT = AI_RULE_HOSTS.flatMap((seg) => seg.doms);
var listRows = (a, n = 6) => a.map((x) => " ".repeat(n) + `- ${JSON.stringify(String(x))}`).join("\n");
function buildRules() {
  const indexed = RULESETS.map(({ group, url }, seq) => ({
    id: `rule${String(seq).padStart(2, "0")}`,
    group,
    url
  }));
  const providers = indexed.map(({ id, url }) => `  ${id}:
    type: http
    behavior: classical
    format: text
    interval: 86400
    url: ${url}
    path: ./ruleset/${id}.list`).join("\n");
  const matched = indexed.map(({ id, group }) => `  - RULE-SET,${id},${group}`);
  const inline = AI_FLAT.map((d) => `  - DOMAIN-SUFFIX,${d},\u{1F916} AI\u670D\u52A1`);
  return { prov: providers, rules: [...inline, ...matched].join("\n") };
}
function commonHeader(flag) {
  const basics = [
    "mixed-port: 7890",
    "allow-lan: false",
    "mode: rule",
    "log-level: info",
    `ipv6: ${flag}`,
    "unified-delay: true",
    "tcp-concurrent: true",
    "find-process-mode: 'off'",
    "external-controller: 127.0.0.1:9090",
    ""
  ];
  const profile = [
    "profile:",
    "  store-selected: true",
    "  store-fake-ip: true",
    ""
  ];
  const sniff = [
    "sniffer:",
    "  enable: true",
    "  sniff:",
    "    HTTP:",
    "      ports: [80, 8080-8880]",
    "      override-destination: true",
    "    TLS:",
    "      ports: [443, 8443]",
    "    QUIC:",
    "      ports: [443, 8443]",
    "  skip-domain:",
    "    - '+.push.apple.com'",
    "    - '+.apple.com'",
    ""
  ];
  const resolver = [
    "dns:",
    "  enable: true",
    "  listen: 0.0.0.0:1053",
    `  ipv6: ${flag}`,
    "  enhanced-mode: fake-ip",
    "  fake-ip-range: 198.18.0.1/16",
    "  fake-ip-filter:",
    "    - '+.lan'",
    "    - '+.local'",
    "    - '*.msftconnecttest.com'",
    "    - '*.msftncsi.com'",
    // bootstrap：只用来解析下面这些 DoH 服务器自己的域名，必须写纯 IP。
    // 文档允许此处为加密 DNS，于是明文 UDP 53 在这份配置里彻底消失。
    "  default-nameserver:",
    "    - https://223.5.5.5/dns-query",
    "    - https://1.12.12.12/dns-query",
    "  nameserver:",
    "    - https://223.5.5.5/dns-query",
    "    - https://1.12.12.12/dns-query",
    // 代理节点域名解析：只能境内直连，否则解析节点域名本身又要先连上节点
    "  proxy-server-nameserver:",
    "    - https://223.5.5.5/dns-query",
    "  nameserver-policy:",
    "    'geosite:cn,private':",
    "      - https://223.5.5.5/dns-query",
    "      - https://1.12.12.12/dns-query",
    // `#组名` 后缀 = 这条 DNS 查询走哪个出口，mihomo 官方语法
    "    'geosite:geolocation-!cn':",
    "      - 'https://1.1.1.1/dns-query#WARP\u76F4\u8FDE'",
    "      - 'https://1.0.0.1/dns-query#WARP\u76F4\u8FDE'"
  ];
  return [...basics, ...profile, ...sniff, ...resolver].join("\n");
}
function buildGroups(entries, topNames, picks, aiPicks, catchPicks) {
  const blocks = [];
  blocks.push([
    `  - name: WARP\u76F4\u8FDE`,
    `    type: url-test`,
    // https + expected-status 204：明文 http 测试会被劫持干扰（mihomo 官方 warning 点名），
    // 严格状态码校验让坏接入点立刻判负；timeout 收紧、失败 3 次即强制重测（快踢）。
    // 测速 URL 用 gstatic 204（1.1.1.1 返回 200，配 204 校验会全组判死）。
    `    url: https://www.gstatic.com/generate_204`,
    `    interval: 300`,
    `    expected-status: 204`,
    `    timeout: 5000`,
    `    max-failed-times: 3`,
    `    tolerance: 50`,
    `    lazy: true`,
    `    proxies:`,
    listRows(entries)
  ].join("\n"));
  if (topNames.length) {
    blocks.push([
      `  - name: top100`,
      `    type: url-test`,
      // 同 WARP 组：https+204 严格校验+快超时+失败 3 次强制重测——MASQUE 底座
      // UDP 抖动时坏节点快速判负踢出，别让浏览器拿着断了的连接报 SSL 错。
      `    url: https://www.gstatic.com/generate_204`,
      `    interval: 180`,
      `    expected-status: 204`,
      `    timeout: 5000`,
      `    max-failed-times: 3`,
      `    tolerance: 100`,
      `    lazy: true`,
      `    proxies:`,
      listRows(topNames)
    ].join("\n"));
  }
  const menu = (label, members) => [`  - name: ${label}`, `    type: select`, `    proxies:`, listRows(members)].join("\n");
  blocks.push(menu("\u{1F680} \u8282\u70B9\u9009\u62E9", picks));
  blocks.push(menu("\u{1F916} AI\u670D\u52A1", aiPicks));
  blocks.push(menu("\u{1F3A5} \u5948\u98DE\u89C6\u9891", aiPicks));
  blocks.push(menu("\u{1F41F} \u6F0F\u7F51\u4E4B\u9C7C", catchPicks));
  return blocks.join("\n\n");
}
var RE_B64_DASH = /-/g;
var RE_B64_SLASH = /_/g;
var RE_DIGITS = /^\d+$/;
var RE_NONPRINT = /[^\x20-\x7e]/;
var RE_PLUS = /\+/g;
var RE_COLON = /:/g;
var RE_HTTPS = /^https:/i;
var RE_CTRL = /[\x00-\x1f\x7f-\x9f]/g;
var RE_CTRL_SCALAR = /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/g;
var b64TextDec = new TextDecoder();
var PROTO_OK = /* @__PURE__ */ new Set([
  "vless",
  "vmess",
  "trojan",
  "ss",
  "hysteria2",
  "hy2",
  "http",
  "socks",
  "socks5"
]);
var b64c = (s) => String(s).replace(RE_B64_DASH, "+").replace(RE_B64_SLASH, "/");
function b64d(s) {
  try {
    const bin = atob(b64c(String(s)));
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return b64TextDec.decode(bytes);
  } catch {
    return String(s ?? "");
  }
}
var j = (s) => JSON.stringify(String(s ?? "").replace(RE_CTRL_SCALAR, ""));
function splitIdent(ident) {
  const s = String(ident ?? "");
  const i = s.lastIndexOf(":");
  if (i > 0 && i < s.length - 1) return { user: s.slice(0, i), pass: s.slice(i + 1) };
  return null;
}
function authFromRaw(raw) {
  const m = /^[A-Za-z0-9+.-]+:\/\/([^@/?#]*)@/.exec(raw);
  if (!m || !m[1]) return null;
  let info = m[1];
  try {
    info = decodeURIComponent(info);
  } catch {
  }
  const cut = info.lastIndexOf(":");
  if (cut <= 0 || cut === info.length - 1) return { user: "", pass: info };
  return { user: info.slice(0, cut), pass: info.slice(cut + 1) };
}
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
  const dec = b64d(info);
  const text = RE_NONPRINT.test(dec) ? info : dec;
  const cut = text.indexOf(":");
  if (cut <= 0 || cut === text.length - 1) return null;
  return { method: text.slice(0, cut), pass: text.slice(cut + 1) };
}
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
    try {
      v = decodeURIComponent(v.replace(RE_PLUS, " "));
    } catch {
    }
    out[k] = v;
  }
  return out;
}
function rawParams(raw) {
  if (!raw) return {};
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
        path: jm.path || "",
        host: jm.host || "",
        alpn: "",
        flow: "",
        fp: "chrome",
        pbk: "",
        sid: "",
        vmessId: jm.id || "",
        alterId: Number(jm.aid) || 0
      };
    } catch {
      return {};
    }
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
    pbk: q.pbk || "",
    sid: q.sid || ""
  };
}
function topProxy(n, name, proto) {
  if (!PROTO_OK.has(proto)) return null;
  const server = String(n?.server ?? "").trim();
  let port = String(n?.port ?? "").trim();
  const slash = port.indexOf("/");
  if (slash >= 0) port = port.slice(0, slash).trim();
  if (!server || !port || !RE_DIGITS.test(port)) return null;
  const ident = String(n?.ident ?? "").trim();
  const raw = String(n?.raw ?? "").trim();
  const p = rawParams(raw);
  const ind = "    ";
  const base = `  - name: ${j(name)}
${ind}type: ${proto}
${ind}server: ${j(server)}
${ind}port: ${j(port)}`;
  const nw = p.network || "tcp";
  let net = "";
  if (nw === "ws") {
    net += `
${ind}network: ws
${ind}ws-opts:
${ind}${ind}path: ${j(p.path || "/")}`;
    if (p.host) net += `
${ind}${ind}headers:
${ind}${ind}${ind}Host: ${j(p.host)}`;
  } else if (nw === "grpc") {
    net += `
${ind}network: grpc
${ind}grpc-opts:
${ind}${ind}grpc-service-name: ${j(p.path || "")}`;
  } else if (nw === "http" || nw === "h2") {
    net += `
${ind}network: http
${ind}http-opts:
${ind}${ind}path: ${j(p.path || "/")}`;
    if (p.host) net += `
${ind}${ind}headers:
${ind}${ind}${ind}Host: ${j(p.host)}`;
  }
  let tls = "";
  if (p.reality) {
    tls = `
${ind}tls: true
${ind}servername: ${j(p.sni || server)}
${ind}reality-opts:
${ind}${ind}public-key: ${j(p.pbk)}` + (p.sid ? `
${ind}${ind}short-id: ${j(p.sid)}` : "");
  } else if (p.tls) {
    tls = `
${ind}tls: true
${ind}servername: ${j(p.sni || server)}
${ind}skip-cert-verify: true`;
  }
  const fp = `
${ind}client-fingerprint: ${j(p.fp || "chrome")}`;
  const alpn = p.alpn ? `
${ind}alpn: [${p.alpn.split(",").map((a) => j(a.trim())).join(", ")}]` : "";
  switch (proto) {
    case "vless": {
      if (!ident) return null;
      const flow = p.flow ? `
${ind}flow: ${j(p.flow)}` : "";
      return `${base}
${ind}uuid: ${j(ident)}${flow}${tls}${net}${fp}${alpn}`;
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
        } catch {
        }
      }
      if (!id) return null;
      return `${base}
${ind}uuid: ${j(id)}
${ind}alterId: ${alterId}
${ind}cipher: auto
${ind}udp: true${tls}${net}${fp}`;
    }
    case "trojan": {
      const pass = authFromRaw(raw)?.pass || ident;
      if (!pass) return null;
      const t = tls || `
${ind}tls: true
${ind}servername: ${j(p.sni || server)}
${ind}skip-cert-verify: true`;
      return `${base}
${ind}password: ${j(pass)}${t}${net}${fp}${alpn}`;
    }
    case "ss": {
      if (!ident) return null;
      let method = "aes-256-gcm", password = ident;
      const via = ssAuthFromRaw(raw);
      if (via) {
        method = via.method;
        password = via.pass;
      } else {
        const dec = b64d(ident);
        if (dec.length > 0 && !RE_NONPRINT.test(dec)) {
          const mp = dec.split(":");
          if (mp.length >= 2) {
            method = mp[0];
            password = mp.slice(1).join(":");
          }
        } else {
          const parts = ident.split(":");
          if (parts.length >= 3) {
            method = parts[0];
            password = parts.slice(1).join(":");
          } else if (parts.length === 2 && parts[0].includes("-")) {
            method = parts[0];
            password = parts[1];
          }
        }
      }
      if (!password) return null;
      return `${base}
${ind}cipher: ${j(method)}
${ind}password: ${j(password)}${net}
${ind}udp: true`;
    }
    case "hysteria2":
    case "hy2": {
      if (!ident) return null;
      return `${base.replace(`type: ${proto}`, "type: hysteria2")}
${ind}password: ${j(ident)}` + (p.tls || p.sni ? `
${ind}sni: ${j(p.sni || server)}` : "") + `
${ind}skip-cert-verify: true`;
    }
    case "http": {
      const via = authFromRaw(raw);
      const up = via?.user ? via : splitIdent(ident);
      let s = base;
      if (up?.user) s += `
${ind}username: ${j(up.user)}
${ind}password: ${j(up.pass)}`;
      else if (via?.pass || ident) s += `
${ind}password: ${j(via?.pass || ident)}`;
      return `${s}
${ind}tls: ${p.tls || RE_HTTPS.test(raw) ? "true" : "false"}`;
    }
    case "socks":
    case "socks5": {
      const via = authFromRaw(raw);
      const up = via?.user ? via : splitIdent(ident);
      let s = base.replace(`type: ${proto}`, "type: socks5");
      if (up?.user) s += `
${ind}username: ${j(up.user)}
${ind}password: ${j(up.pass)}`;
      else if (via?.pass || ident) s += `
${ind}password: ${j(via?.pass || ident)}`;
      return `${s}
${ind}udp: true`;
    }
    default:
      return null;
  }
}
var stampOf = (yaml) => /# 由 Cloudflare Worker 生成于 ([^\n]+)/.exec(yaml)?.[1] || null;
var withoutStamp = (yaml) => yaml.replace(/# 由 Cloudflare Worker 生成于 [^\n]+/, "# \u7531 Cloudflare Worker \u751F\u6210\u4E8E @");
function buildConfig(warp, warpEp, top100Nodes, dataStamp) {
  const { entries, proxies } = assembleEndpoints(warp, warpEp);
  const topNames = [];
  const topProxies = [];
  const usedNames = /* @__PURE__ */ new Set();
  (Array.isArray(top100Nodes) ? top100Nodes : []).forEach((n, i) => {
    const proto0 = String(n?.proto || "?").toLowerCase();
    const name = topName(n?.geo, n?.server, n?.port, usedNames);
    const y = topProxy(n, name, proto0.trim());
    if (y) {
      topNames.push(name);
      topProxies.push(`${y}
    dialer-proxy: "WARP\u76F4\u8FDE"`);
    }
  });
  const picks = ["WARP\u76F4\u8FDE"];
  if (topNames.length) picks.push("top100");
  const aiPicks = topNames.length ? ["top100", "WARP\u76F4\u8FDE", "\u{1F680} \u8282\u70B9\u9009\u62E9"] : ["WARP\u76F4\u8FDE", "\u{1F680} \u8282\u70B9\u9009\u62E9"];
  const catchPicks = topNames.length ? ["\u{1F680} \u8282\u70B9\u9009\u62E9", "top100", "WARP\u76F4\u8FDE"] : ["\u{1F680} \u8282\u70B9\u9009\u62E9", "WARP\u76F4\u8FDE"];
  const { prov, rules } = buildRules();
  const groups = buildGroups(entries, topNames, picks, aiPicks, catchPicks);
  const stamp = dataStamp || (/* @__PURE__ */ new Date()).toISOString();
  const head = `# WARP MASQUE \u76F4\u8FDE + top100 \u7CBE\u9009
# \u7531 Cloudflare Worker \u751F\u6210\u4E8E ${stamp}
#
#   WARP\u76F4\u8FDE   \u672C\u673A -> MASQUE -> \u76EE\u6807\uFF08\u51FA\u53E3\u662F CF \u81EA\u5DF1\u7684 IP\uFF0C\u515C\u5E95\u4FDD\u5E95\uFF09
#   top100     top100 \u7CBE\u9009\u6E90${topNames.length ? `\uFF08${topNames.length} \u4E2A\uFF0Curl-test \u81EA\u52A8\u6311\u6700\u5FEB\uFF09` : "\uFF08KV \u6682\u65E0\u6570\u636E\uFF0C\u4EC5\u4FDD\u7559 WARP\uFF09"}
#
# \u5206\u6D41\u53EA\u6709\u56DB\u7C7B\uFF0C\u6309\u5E8F\uFF1A
#   1) AI \u57DF\u540D     -> \u{1F916} AI\u670D\u52A1
#   2) \u5948\u98DE        -> \u{1F3A5} \u5948\u98DE\u89C6\u9891
#   3) \u5C40\u57DF\u7F51+\u4E2D\u56FD -> DIRECT
#   4) \u5176\u4F59\u5168\u90E8    -> \u{1F41F} \u6F0F\u7F51\u4E4B\u9C7C\uFF08MATCH \u515C\u5E95\uFF09
#
# \u63A5\u5165\u70B9 ${entries.length} \u4E2A${topNames.length ? ` + top100 \u8282\u70B9 ${topNames.length} \u4E2A` : ""}\uFF0C
# \u4EFB\u4E00\u73AF\u5931\u6548\u90FD\u6709\u66FF\u4EE3\u8DEF\u5F84\u3002
#
# \u9700\u8981 mihomo Alpha \u5206\u652F\uFF1A\u7A33\u5B9A\u7248\u6CA1\u6709 masque outbound\u3002
# private-key \u7B49\u540C WARP \u8D26\u53F7\u51ED\u636E\uFF0C\u522B\u5916\u4F20\u3002

${commonHeader(true)}

proxies:
${[...proxies, ...topProxies].join("\n")}

proxy-groups:
${groups}
`;
  const tail = [
    "",
    "rule-providers:",
    prov,
    "",
    "rules:",
    rules,
    "  - GEOIP,LAN,DIRECT,no-resolve",
    "  - GEOIP,CN,DIRECT",
    "  - MATCH,\u{1F41F} \u6F0F\u7F51\u4E4B\u9C7C",
    ""
  ].join("\n");
  const yaml = head + tail;
  return {
    yaml,
    entries: entries.length,
    warpEndpoints: entries.length,
    top100: topNames.length
  };
}

// worker/src/auth.js
var utf8 = new TextEncoder();
var ROUNDS = 21e4;
var toBase642 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
var fromBase64 = (s) => Uint8Array.from(atob(s), (ch) => ch.charCodeAt(0));
async function sha256(text) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(text)));
}
async function sameSecret(a, b) {
  const [x, y] = await Promise.all([sha256(a || ""), sha256(b || "")]);
  let acc = 0;
  for (let i = 0; i < 32; i++) acc |= x[i] ^ y[i];
  return acc === 0;
}
async function stretch(plain, saltText, times = ROUNDS) {
  const mat = await crypto.subtle.importKey(
    "raw",
    utf8.encode(plain),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: fromBase64(saltText), iterations: times, hash: "SHA-256" },
    mat,
    256
  );
  return toBase642(bits);
}
async function createCred(plain) {
  const seed = crypto.getRandomValues(new Uint8Array(16));
  const salt = toBase642(seed);
  return {
    salt,
    iter: ROUNDS,
    hash: await stretch(plain, salt, ROUNDS),
    updatedAt: (/* @__PURE__ */ new Date()).toISOString()
  };
}
async function passwordMatches(cred, plain) {
  if (!cred?.hash) return false;
  const recalc = await stretch(plain, cred.salt, cred.iter || ROUNDS);
  return sameSecret(recalc, cred.hash);
}
async function signWith(keyText, payload) {
  const key = await crypto.subtle.importKey(
    "raw",
    utf8.encode(keyText),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, utf8.encode(payload));
  return toBase642(mac).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
var SESSION_MS = 7 * 24 * 3600 * 1e3;
async function mintToken(cred) {
  const deadline = Date.now() + SESSION_MS;
  return `${deadline}.${await signWith(cred.hash, String(deadline))}`;
}
async function checkToken(cred, token) {
  if (!cred?.hash || !token) return false;
  const cut = token.lastIndexOf(".");
  if (cut < 1) return false;
  const deadline = token.slice(0, cut);
  const mac = token.slice(cut + 1);
  if (!/^\d+$/.test(deadline) || Number(deadline) < Date.now()) return false;
  return sameSecret(mac, await signWith(cred.hash, deadline));
}
function cookieValue(req, name) {
  const header = req.headers.get("cookie") || "";
  for (const pair of header.split(";")) {
    const eq = pair.trim().indexOf("=");
    if (eq > 0 && pair.trim().slice(0, eq) === name) return pair.trim().slice(eq + 1);
  }
  return null;
}
var LIMIT_KEY = (ip) => `rl:${ip}`;
var MAX_TRIES = 8;
var LOCK_TTL = 900;
async function attemptAllowed(env, ip) {
  const hits = Number(await env.KV.get(LIMIT_KEY(ip)) || 0);
  if (hits >= MAX_TRIES) return false;
  await env.KV.put(LIMIT_KEY(ip), String(hits + 1), { expirationTtl: LOCK_TTL });
  return true;
}
async function resetAttemptLimit(env, ip) {
  await env.KV.delete(LIMIT_KEY(ip));
}
var RESERVED = /* @__PURE__ */ new Set(["login", "logout", "api", "setup"]);
var SUB_PATTERN = /^[A-Za-z0-9_-]{1,64}$/;
function sanitizeSubPath(input) {
  const seg = String(input || "").trim().replace(/^\/+|\/+$/g, "");
  if (!seg || !SUB_PATTERN.test(seg)) return null;
  return RESERVED.has(seg.toLowerCase()) ? null : seg;
}

// worker/src/index.js
var KEY_DEVICE = "warp:device";
var KEY_YAML = "config:yaml";
var KEY_META = "state:meta";
var KEY_CRED = "auth:cred";
var KEY_SETTINGS = "settings";
var KEY_SETUP_LOCK = "auth:claim";
var KEY_TRIGGER = "proton:token";
var KEY_ENDPOINTS = "warp:endpoints";
var KEY_TOP100 = "top100:nodes";
var KEY_BUILD_LOCK = "rebuild:lock";
var SESSION_COOKIE = "om_session";
var FALLBACK_SUB = "sub";
var TRAILING_SLASH = /\/+$/;
var CONFIG_LIFE_MS = 4 * 60 * 60 * 1e3;
var EXPIRE_MARGIN_MS = 10 * 60 * 1e3;
var reply = (obj, code = 200) => new Response(JSON.stringify(obj), {
  status: code,
  headers: { "content-type": "application/json; charset=utf-8" }
});
var page = (body, code = 200) => new Response(body, {
  status: code,
  headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }
});
var noRoute = () => new Response("Not Found", { status: 404 });
var SESSION_TTL_S = 7 * 24 * 3600;
var withSession = (obj, token) => new Response(JSON.stringify(obj), {
  headers: {
    "content-type": "application/json; charset=utf-8",
    "set-cookie": `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${SESSION_TTL_S}`
  }
});
async function runRebuild(env, opts, fmt) {
  const gate = await withBuildLock(env, () => regenConfig(env, opts));
  if (!gate.held) return reply({ ok: false, error: "\u91CD\u5EFA\u8FDB\u884C\u4E2D\uFF0C\u8BF7\u7A0D\u540E\u518D\u8BD5" }, 409);
  if (gate.error) {
    console.error("[worker] \u91CD\u5EFA\u5931\u8D25:", gate.error);
    return reply({ ok: false, error: "\u91CD\u5EFA\u5931\u8D25\uFF0C\u8BF7\u7A0D\u540E\u518D\u8BD5" }, 500);
  }
  return reply(fmt(gate.result.meta));
}
var taken = () => reply({ ok: false, error: "\u7BA1\u7406\u5458\u53E3\u4EE4\u5DF2\u5B58\u5728\uFF0C\u65E0\u9700\u91CD\u590D\u521D\u59CB\u5316" }, 409);
var MIN_LEN = 12;
var WEAK = /* @__PURE__ */ new Set([
  "password",
  "password1",
  "password123",
  "12345678",
  "123456789",
  "1234567890",
  "qwertyuiop",
  "qwerty123",
  "iloveyou",
  "admin123",
  "administrator",
  "letmein123",
  "welcome123",
  "top100",
  "top100top100",
  "abc123456",
  "passw0rd",
  "p@ssw0rd",
  "football123",
  "monkey123"
]);
function pwDefect(pw, confirm, fresh) {
  if (pw.length < MIN_LEN) return fresh ? "\u65B0\u53E3\u4EE4\u957F\u5EA6\u81F3\u5C11 12 \u4F4D" : "\u53E3\u4EE4\u957F\u5EA6\u81F3\u5C11 12 \u4F4D";
  if (pw !== String(confirm ?? "")) return "\u4E24\u6B21\u8F93\u5165\u7684\u53E3\u4EE4\u4E0D\u4E00\u81F4";
  if (WEAK.has(pw.toLowerCase())) return "\u53E3\u4EE4\u8FC7\u4E8E\u5E38\u89C1\uFF0C\u8BF7\u6362\u4E00\u4E2A";
  return null;
}
var readBody = (req) => req.json().catch(() => ({}));
var SUB_HEADERS = {
  "content-type": "text/yaml; charset=utf-8",
  "content-disposition": "attachment; filename=opera-masque.yaml",
  "profile-update-interval": "4",
  "cache-control": "no-cache"
};
var TEXT = new TextEncoder();
async function bodyTag(body) {
  try {
    const raw = await crypto.subtle.digest("SHA-256", TEXT.encode(body));
    const view = new Uint8Array(raw);
    let hex = "";
    for (let i = 0; i < 16; i++) hex += view[i].toString(16).padStart(2, "0");
    return `"${hex}"`;
  } catch {
    return null;
  }
}
function tagMatches(ifNoneMatch, tag) {
  if (!ifNoneMatch || !tag) return false;
  const bare = (v) => v.trim().replace(/^W\//, "");
  const target = bare(tag);
  return ifNoneMatch.split(",").some((candidate) => {
    const item = bare(candidate);
    return item === "*" || item === target;
  });
}
async function loadSettings(env) {
  let raw = null;
  try {
    raw = await env.KV.get(KEY_SETTINGS, "json");
  } catch {
    raw = null;
  }
  if (!raw || typeof raw !== "object") raw = {};
  return { subPath: String(raw.subPath || FALLBACK_SUB) };
}
async function credIssued(env) {
  try {
    return !!await env.KV.get(KEY_CRED, "json");
  } catch {
    return false;
  }
}
async function loadWarp(env, force = false) {
  if (!force) {
    let cache = null;
    try {
      cache = await env.KV.get(KEY_DEVICE, "json");
    } catch {
      cache = null;
    }
    if (warpUsable(cache)) return cache;
  }
  const fresh = await enrollWarpDevice("cf-worker");
  await env.KV.put(KEY_DEVICE, JSON.stringify(fresh));
  return fresh;
}
async function regenConfig(env, { forceWarp = false } = {}) {
  const warp = await loadWarp(env, forceWarp);
  let tuned = null;
  try {
    const raw = await env.KV.get(KEY_ENDPOINTS);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (parsed && Array.isArray(parsed.picked)) tuned = parsed;
    }
  } catch {
    tuned = null;
  }
  let dataAt = null;
  let batch = [];
  try {
    const raw = await env.KV.get(KEY_TOP100);
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) batch = parsed;
      else if (parsed && Array.isArray(parsed.nodes)) {
        batch = parsed.nodes;
        dataAt = typeof parsed.generated_at === "string" ? parsed.generated_at : null;
      }
    }
  } catch {
    batch = [];
  }
  const prev = await env.KV.get(KEY_YAML).catch(() => null);
  const carry = dataAt || (prev ? stampOf(prev) : null);
  let out = buildConfig(warp, tuned, batch, carry);
  if (prev && withoutStamp(prev) !== withoutStamp(out.yaml)) {
    out = buildConfig(warp, tuned, batch, (/* @__PURE__ */ new Date()).toISOString());
  }
  const { yaml, entries, warpEndpoints: we, top100: t100 } = out;
  const stamp = Date.now();
  const warpDigest = ["deviceId", "ipv4", "ipv6", "registeredAt"].reduce((acc, field) => ({ ...acc, [field]: warp[field] }), {});
  const meta = {
    updatedAt: new Date(stamp).toISOString(),
    expiresAt: new Date(stamp + CONFIG_LIFE_MS).toISOString(),
    dataAt: stampOf(yaml),
    // 精简后的 stats：只留 WARP 相关 + top100 计数
    stats: {
      entries: entries || 0,
      warpEndpoints: we || 0,
      top100: t100 || 0,
      top100Raw: batch.length
    },
    warp: warpDigest
  };
  await env.KV.put(KEY_YAML, yaml);
  await env.KV.put(KEY_META, JSON.stringify(meta));
  return { meta, yaml };
}
function withinTtl(meta) {
  if (!meta?.expiresAt) return false;
  return Date.parse(meta.expiresAt) - EXPIRE_MARGIN_MS > Date.now();
}
async function claimBuildLock(env) {
  let held = null;
  try {
    held = await env.KV.get(KEY_BUILD_LOCK);
  } catch {
    held = null;
  }
  if (held !== null && held !== "") {
    const at = Number(held);
    if (Number.isNaN(at) || Date.now() - at < 9e4) return false;
  }
  const mine = `lock:${crypto.randomUUID()}`;
  await env.KV.put(KEY_BUILD_LOCK, mine, { expirationTtl: 120 });
  try {
    if (await env.KV.get(KEY_BUILD_LOCK) !== mine) return false;
    if (await env.KV.get(KEY_BUILD_LOCK) !== mine) return false;
    return true;
  } catch {
    return false;
  }
}
async function withBuildLock(env, task) {
  if (!await claimBuildLock(env)) return { held: false };
  try {
    return { held: true, result: await task() };
  } catch (e) {
    return { held: true, error: e };
  } finally {
    try {
      await env.KV.delete(KEY_BUILD_LOCK);
    } catch {
    }
  }
}
async function currentConfig(env) {
  const [meta, cached] = await Promise.all([
    env.KV.get(KEY_META, "json").catch(() => null),
    env.KV.get(KEY_YAML).catch(() => null)
  ]);
  if (cached && withinTtl(meta)) return cached;
  const gate = await withBuildLock(env, () => regenConfig(env));
  if (gate.held) {
    if (gate.error) {
      console.error("[worker] \u91CD\u5EFA\u5931\u8D25\uFF0C\u964D\u7EA7\u56DE\u65E7\u6B63\u6587:", gate.error);
      return cached;
    }
    return gate.result?.yaml || cached;
  }
  console.warn("[worker] \u91CD\u5EFA\u9501\u88AB\u5360\u7528\uFF0C\u8D70\u65E7\u914D\u7F6E\u9876\u66FF");
  if (cached) return cached;
  try {
    return await env.KV.get(KEY_YAML) || null;
  } catch (e) {
    console.error("[worker] \u672B\u5C3E\u56DE\u8BFB config:yaml \u5931\u8D25\uFF0C\u964D\u7EA7 503:", e);
    return null;
  }
}
async function dispatch(req, env) {
  const url = new URL(req.url);
  const path = url.pathname.replace(TRAILING_SLASH, "") || "/";
  if (!env || !env.KV) return page("KV \u672A\u7ED1\u5B9A\uFF0C\u8BF7\u5148\u7ED1\u5B9A KV \u7A7A\u95F4", 500);
  let cred = null;
  try {
    cred = await env.KV.get(KEY_CRED, "json");
  } catch {
    cred = null;
  }
  let authed = cred && await checkToken(cred, cookieValue(req, SESSION_COOKIE));
  if (!cred) {
    if (path === "/api/setup" && req.method === "POST") {
      const form = await readBody(req);
      const defect = pwDefect(String(form.password || ""), form.confirm, false);
      if (defect) return reply({ ok: false, error: defect }, 400);
      const claim = crypto.randomUUID();
      if (await credIssued(env)) return taken();
      await env.KV.put(KEY_SETUP_LOCK, claim, { expirationTtl: 60 });
      if (await env.KV.get(KEY_SETUP_LOCK) !== claim) return taken();
      const c = await createCred(String(form.password || ""));
      if (await credIssued(env)) return taken();
      await env.KV.put(KEY_CRED, JSON.stringify(c));
      await env.KV.delete(KEY_SETUP_LOCK);
      return withSession({ ok: true }, await mintToken(c));
    }
    return noRoute();
  }
  const settings = await loadSettings(env);
  const routePath = "/" + settings.subPath;
  if (path === routePath) {
    const t = url.searchParams.get("token") || "";
    if (t && !await checkToken(cred, t) && !authed) return noRoute();
    const yaml = await currentConfig(env);
    if (!yaml) {
      const plain = { status: 503, headers: { "content-type": "text/plain; charset=utf-8" } };
      return new Response("\u8BA2\u9605\u914D\u7F6E\u6682\u4E0D\u53EF\u7528\uFF0C\u8BF7\u7A0D\u540E\u518D\u53D6", plain);
    }
    const tag = await bodyTag(yaml);
    const headers = { ...SUB_HEADERS };
    if (tag) headers.etag = tag;
    if (tag && tagMatches(req.headers.get("if-none-match"), tag)) {
      return new Response(null, { status: 304, headers });
    }
    return new Response(yaml, { headers });
  }
  if (path.startsWith("/push/") && req.method === "POST") {
    const tk = await env.KV.get(KEY_TRIGGER);
    const tail = path.slice(6);
    const sep = tail.indexOf("/");
    const keyPart = sep < 0 ? tail : tail.slice(0, sep);
    const action = sep < 0 ? "" : tail.slice(sep + 1);
    if (!tk || !keyPart || !await sameSecret(keyPart, tk)) return noRoute();
    if (action && action !== "rebuild") return noRoute();
    return runRebuild(
      env,
      void 0,
      (m) => ({ ok: true, msg: `\u5DF2\u91CD\u5EFA\uFF0Ctop100 ${m.stats.top100} \u4E2A`, stats: m.stats })
    );
  }
  if (!authed) return noRoute();
  if (path === "/api/sub-path" && req.method === "POST") {
    const form = await readBody(req);
    const next = sanitizeSubPath(form.path);
    if (!next) {
      return reply({
        ok: false,
        error: "\u4EC5\u9650\u5B57\u6BCD\u6570\u5B57\u4E0E - _\uFF0C\u957F\u5EA6 1-64\uFF0C\u4E14\u4E0D\u53EF\u7528 login/logout/api/setup"
      }, 400);
    }
    await env.KV.put(KEY_SETTINGS, JSON.stringify({ ...settings, subPath: next }));
    return reply({ ok: true, msg: `\u8BA2\u9605\u8DEF\u5F84\u5DF2\u6539\u4E3A /${next}` });
  }
  if (path === "/api/password" && req.method === "POST") {
    const form = await readBody(req);
    const ip = req.headers.get("cf-connecting-ip") || "";
    if (!await passwordMatches(cred, String(form.current || ""))) {
      if (ip && !await attemptAllowed(env, ip)) {
        return reply({ ok: false, error: "\u5C1D\u8BD5\u8FC7\u4E8E\u9891\u7E41\uFF0C\u8BF7 15 \u5206\u949F\u540E\u518D\u8BD5" }, 429);
      }
      return reply({ ok: false, error: "\u5F53\u524D\u53E3\u4EE4\u6821\u9A8C\u5931\u8D25" }, 401);
    }
    if (ip) await resetAttemptLimit(env, ip);
    const fresh = String(form.password || "");
    const defect = pwDefect(fresh, form.confirm, true);
    if (defect) return reply({ ok: false, error: defect }, 400);
    const c = await createCred(fresh);
    await env.KV.put(KEY_CRED, JSON.stringify(c));
    return withSession(
      { ok: true, msg: "\u53E3\u4EE4\u5DF2\u66F4\u65B0\uFF0C\u65E7\u4F1A\u8BDD\u4E0E\u65E7\u8BA2\u9605\u94FE\u63A5\u5168\u90E8\u4F5C\u5E9F" },
      await mintToken(c)
    );
  }
  if (path === "/api/refresh" && req.method === "POST") {
    return runRebuild(
      env,
      void 0,
      (m) => ({ ok: true, msg: `\u5DF2\u5237\u65B0\uFF0Ctop100 ${m.stats.top100} \u4E2A`, stats: m.stats })
    );
  }
  if (path === "/api/reset-warp" && req.method === "POST") {
    return runRebuild(
      env,
      { forceWarp: true },
      (m) => ({ ok: true, msg: "WARP \u5DF2\u91CD\u6CE8\u518C", stats: m.stats })
    );
  }
  return noRoute();
}
var routes = {
  fetch: async (req, env) => {
    const res = await dispatch(req, env);
    res.headers.set("x-content-type-options", "nosniff");
    res.headers.set("Referrer-Policy", "no-referrer");
    return res;
  }
};
var index_default = routes;
self.addEventListener('fetch', (event) => { event.respondWith(index_default.fetch(event.request, { KV: KV })); });
