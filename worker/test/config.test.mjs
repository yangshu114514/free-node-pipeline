// 配置回归测试（跑: node test/config.test.mjs）。
// 核验面：策略组构成（空/满 top100 两态）、成员引用完整性、
// 规则四分类与规则集清单、链式代理防环、接入点精选与回退。
import { buildConfig } from "../src/config.js";

// 测试用 WARP 凭据（假值，只验结构）
const ACCESS = {
  privateKey: "MGsCAQEEIFAKE",
  peerPublicKey: "MFkwEwFAKE",
  ipv4: "172.16.0.2",
  ipv6: "2606:4700:110::1",
  deviceId: "x",
  registeredAt: new Date().toISOString(),
};

let hits = 0;
let misses = 0;
const probe = (desc, ok) => {
  if (ok) {
    hits += 1;
    console.log("  ✔", desc);
  } else {
    misses += 1;
    console.log("  ✘", desc);
  }
};
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// 早前架构已裁撤的组：一旦出现在组名、成员引用或规则目标里即为回归
const RETIRED = [
  "♻️ 自动选择",
  "🔄 故障转移",
  "Ⓜ️ 微软服务",
  "🌍 国外媒体",
  "🍃 应用净化",
  "🍎 苹果服务",
  "📢 谷歌FCM",
  "📲 电报信息",
  "📹 油管视频",
  "🎯 全球直连",
  "🛑 全球拦截",
];

// ---- 解析辅助 ----
// 组名只在 proxy-groups 与 rule-providers 之间出现，proxies 段的节点行长得一样，必须圈定窗口
const groupsIn = (yml) => [
  ...yml.slice(yml.indexOf("proxy-groups:"), yml.indexOf("rule-providers:"))
    .matchAll(/^  - name: (.+)$/gm),
].map((m) => m[1]);
// 单个组的定义体（截到下一个组开头）
const block = (yml, group) => yml.split(`  - name: ${group}`)[1].split("\n  - name:")[0];
// 组成员行（渲染时有的带引号有的不带，正则里一并吞掉）
const roster = (seg) => [...seg.matchAll(/^      - "?([^"\n]+?)"?$/gm)].map((m) => m[1]);
const rosterOf = (yml, group) => roster(block(yml, group));

// ---- 场景一：没有 top100 精选源 ----
// buildConfig 三参：WARP 凭据 / warp:endpoints 实测（null 表示回退全量接入点）/ top100 节点
const base = buildConfig(ACCESS, null, []);
const B = base.yaml;
const baseGroups = groupsIn(B);
const plainNodes = [...B.matchAll(/^  - \{name: "([^"]+)"/gm)].map((m) => m[1]);
const baseEntries = [...B.matchAll(/^  - name: (\S+)\n    type: masque$/gm)].map((m) => m[1]);

probe(`接入点数量 ${base.entries}`, base.entries === 57);
probe("存在 WARP直连 组", baseGroups.includes("WARP直连"));
probe("空精选态恰好 5 个组", same([...baseGroups].sort(), [
  "WARP直连", "🚀 节点选择", "🤖 AI服务", "🎥 奈飞视频", "🐟 漏网之鱼",
].sort()));
probe("已裁撤组未出现在组名里", RETIRED.filter((g) => baseGroups.includes(g)).length === 0);
probe("已裁撤组未渗入全文", RETIRED.filter((g) => B.includes(g)).length === 0);
probe("没有线路类分组", !baseGroups.some((g) => g.includes("线路")));
probe("全文无「线路」字样", !B.includes("线路"));

probe(`WARP直连 成员数 ${rosterOf(B, "WARP直连").length}`, rosterOf(B, "WARP直连").length === 57);
probe("WARP直连 成员均为裸接入点", rosterOf(B, "WARP直连").every((m) => !m.includes("@")));
probe("WARP直连 成员全部有定义", rosterOf(B, "WARP直连").every((m) => baseEntries.includes(m)));

// 空精选态下各组成员的精确序列（此时任何组都不该引用 top100）
const ROSTER_IDLE = new Map([
  ["🚀 节点选择", ["WARP直连"]],
  ["🤖 AI服务", ["WARP直连", "🚀 节点选择"]],
  ["🎥 奈飞视频", ["WARP直连", "🚀 节点选择"]],
  ["🐟 漏网之鱼", ["🚀 节点选择", "WARP直连"]],
]);
for (const [group, want] of ROSTER_IDLE) {
  probe(`${group} 成员序列`, same(rosterOf(B, group), want));
}
probe("节点选择 未混入裁撤组", !RETIRED.some((g) => block(B, "🚀 节点选择").includes(g)));

// 悬空引用：组成员里出现但从未被 proxies/组/DIRECT/REJECT 定义的名字
const window = B.slice(B.indexOf("proxy-groups:"), B.indexOf("rule-providers:"));
const cited = [...window.matchAll(/^      - "?([^"\n]+)"?$/gm)].map((m) => m[1].trim());
const catalog = new Set([...baseGroups, ...plainNodes, ...baseEntries, "DIRECT", "REJECT"]);
const orphans = [...new Set(cited.filter((c) => !catalog.has(c)))];
probe(`无悬空成员引用${orphans.length ? " → " + orphans.slice(0, 3) : ""}`, orphans.length === 0);

// 规则目标同样不得指向裁撤组
probe("规则未指向裁撤组", RETIRED.filter((g) => B.includes("," + g)).length === 0);

// ---- 场景二：带 top100 精选源 ----
{
  const sample = { proto: "vless", server: "1.2.3.4", port: "443", ident: "test-uuid-000", geo: "JP" };
  const full = buildConfig(ACCESS, null, [sample]);
  const F = full.yaml;
  const fullGroups = groupsIn(F);

  probe("出现 top100 组", fullGroups.includes("top100"));
  probe("满精选态恰好 6 个组", same([...fullGroups].sort(), [
    "WARP直连", "top100", "🚀 节点选择", "🤖 AI服务", "🎥 奈飞视频", "🐟 漏网之鱼",
  ].sort()));
  probe("top100 是 url-test 类型", /- name: top100\n    type: url-test/.test(F));
  probe("vless 节点已渲染（名=地区-IP）", F.includes('name: "JP-1.2.3.4"'));
  probe("vless 节点带 uuid", F.includes('uuid: "test-uuid-000"'));
  probe(`top100 计数 ${full.top100}`, full.top100 === 1);
  probe("节点选择 引用了 top100", block(F, "🚀 节点选择").includes("top100"));

  // 满精选态的成员序列规格
  const ROSTER_FULL = new Map([
    ["🚀 节点选择", ["WARP直连", "top100"]],
    ["🤖 AI服务", ["top100", "WARP直连", "🚀 节点选择"]],
    ["🎥 奈飞视频", ["top100", "WARP直连", "🚀 节点选择"]],
    ["🐟 漏网之鱼", ["🚀 节点选择", "top100", "WARP直连"]],
  ]);
  for (const [group, want] of ROSTER_FULL) {
    probe(`${group} 满态成员序列`, same(rosterOf(F, group), want));
  }

  // 防环：dialer 只能指向 WARP直连。若指组，组成员含 top100 自身，
  // 选中时会走 dialer→组→top100→dialer 死循环，mihomo 拒连甚至崩内核
  probe("top100 节点挂 dialer-proxy 到 WARP直连", F.includes('dialer-proxy: "WARP直连"'));
  probe("dialer 未指向自动选择（防环）", !F.includes('dialer-proxy: "♻️ 自动选择"'));

  // 空数组 → 整组不生成（文件头注释仍带 top100 字样，断言必须锚定组名）
  const none = groupsIn(buildConfig(ACCESS, null, []).yaml);
  probe("空精选不生成 top100 组", !none.includes("top100"));
  probe("空精选时节点选择也不引用", !block(buildConfig(ACCESS, null, []).yaml, "🚀 节点选择").includes("top100"));
}

// ---- 场景三：warp:endpoints 实测精选 / null 回退 ----
{
  const picked = ["198.1-443", "198.2-443", "199.1-443", "199.2-443"];
  const pickedRun = buildConfig(ACCESS, { picked }, []);
  const roster = rosterOf(pickedRun.yaml, "WARP直连");
  probe(`精选生效 WARP直连 ${roster.length} 个`, roster.length === 5);
  probe("picked 命中全部入组", picked.every((n) => roster.includes(n)));
  probe("官方域名兜底在列", roster.includes("官方域名"));
  probe(`精选态接入点 ${pickedRun.entries} 个`, pickedRun.entries === 5);

  const fallback = buildConfig(ACCESS, null, []);
  probe(`null 回退全量 ${fallback.entries} 个`, fallback.entries === 57);
  probe("回退态仍生成 WARP直连", fallback.yaml.includes("  - name: WARP直连"));
}

// ---- 场景四：AI 分组 ----
{
  const A = buildConfig(ACCESS, null, []).yaml;
  const names = groupsIn(A);

  probe("存在 AI服务 组", names.includes("🤖 AI服务"));
  probe("旧 OpenAi 组名已废弃", !names.includes("🤖 OpenAi"));
  probe("无指向 OpenAi 的残留规则", !A.includes(",🤖 OpenAi"));

  // 头部厂商必须逐一命中
  const REQUIRED_HOUSES = [
    "anthropic.com", "grok.com", "perplexity.ai", "deepseek.com",
    "midjourney.com", "huggingface.co", "cursor.com", "elevenlabs.io",
    "mistral.ai", "meta.ai", "openrouter.ai", "kimi.com",
  ];
  const absent = REQUIRED_HOUSES.filter((d) => !A.includes(`DOMAIN-SUFFIX,${d},🤖 AI服务`));
  probe(`头部厂商全覆盖${absent.length ? " 缺:" + absent.slice(0, 3) : ""}`, absent.length === 0);

  // 共用大厂域名混进来会把无关流量拖进 AI 分组
  const SHARED_ROOTS = ["googleapis.com", "cloudflare.com", "stripe.com", "sentry.io", "bing.com"];
  const widened = SHARED_ROOTS.filter((d) => A.includes(`DOMAIN-SUFFIX,${d},🤖 AI服务`));
  probe(`未混入共用域名${widened.length ? " → " + widened : ""}`, widened.length === 0);

  // 内联条目必须先于 RULE-SET，否则让位给上游更宽的规则就白配了
  const firstRuleSet = A.indexOf("  - RULE-SET,");
  const firstInline = A.indexOf("  - DOMAIN-SUFFIX,");
  probe("内联 AI 规则先于 RULE-SET", firstInline > 0 && firstInline < firstRuleSet);

  const aiDomains = [...A.matchAll(/^  - DOMAIN-SUFFIX,([^,]+),🤖 AI服务$/gm)].map((m) => m[1]);
  probe(`AI 域名 ${aiDomains.length} 条无重复`, new Set(aiDomains).size === aiDomains.length);

  const aiBlock = block(A, "🤖 AI服务");
  probe("AI服务 可切换到 节点选择", aiBlock.includes("🚀 节点选择"));
  probe("AI服务 可回落到 WARP直连", aiBlock.includes("WARP直连"));
  probe("AI服务 未引用裁撤组", !RETIRED.some((g) => aiBlock.includes(g)));
}

// ---- 场景五：四类规则 + 规则集下载清单 ----
{
  const R = buildConfig(ACCESS, null, []).yaml;
  const ruleSeg = R.slice(R.indexOf("\nrules:"));
  const provSeg = R.slice(R.indexOf("rule-providers:"), R.indexOf("\nrules:"));

  probe("局域网/中国走 GEOIP 直连",
    R.includes("  - GEOIP,LAN,DIRECT,no-resolve") && R.includes("  - GEOIP,CN,DIRECT"));
  probe("MATCH 兜底落 漏网之鱼", R.includes("  - MATCH,🐟 漏网之鱼"));

  const targets = [...ruleSeg.matchAll(/^  - RULE-SET,[^,]+,(.+)$/gm)].map((m) => m[1]);
  const LEGAL = new Set(["🤖 AI服务", "🎥 奈飞视频", "DIRECT"]);
  const illegal = [...new Set(targets.filter((x) => !LEGAL.has(x)))];
  probe(`RULE-SET 目标合法${illegal.length ? " → " + illegal : ""}`, illegal.length === 0);
  probe(`RULE-SET 分布 AI6/奈飞1/直连3（实得 ${targets.length}）`,
    targets.filter((x) => x === "🤖 AI服务").length === 6 &&
    targets.filter((x) => x === "🎥 奈飞视频").length === 1 &&
    targets.filter((x) => x === "DIRECT").length === 3);

  // 总条数恒等式：内联 AI + 10 条 RULE-SET + 2 条 GEOIP + 1 条 MATCH
  const total = [...ruleSeg.matchAll(/^  - /gm)].length;
  const inline = [...ruleSeg.matchAll(/^  - DOMAIN-SUFFIX,/gm)].length;
  probe(`规则总数 ${total} = 内联 ${inline} + 13`, total === inline + 13);

  const providerUrls = [...provSeg.matchAll(/^    url: (\S+)$/gm)].map((m) => m[1]);
  probe(`规则集下载项 ${providerUrls.length} 个`, providerUrls.length === 10);
  const RETIRED_SETS = [
    "Telegram", "YouTube", "BanAD", "BanProgramAD", "Microsoft", "Apple",
    "GoogleFCM", "SteamCN", "ProxyMedia", "Emby", "ProxyLite", "CMBlog",
    "UnBan", "CFnat", "GoogleCN", "adobe", "IDM",
  ];
  const stillFetching = RETIRED_SETS.filter((s) => providerUrls.some((u) => u.includes(s)));
  probe(`裁撤规则集已停更${stillFetching.length ? " → " + stillFetching : ""}`, stillFetching.length === 0);
  const ACTIVE_SETS = ["OpenAi.list", "Netflix.list", "LocalAreaNetwork.list", "ChinaDomain.list"];
  const dropped = ACTIVE_SETS.filter((s) => !providerUrls.some((u) => u.includes(s)));
  probe(`在用规则集齐备${dropped.length ? " 缺:" + dropped : ""}`, dropped.length === 0);
}

// ---- 场景六：注入面与修复回归（P1-4 / P1-5 / 规则集路径 / 组测速参数）----
{
  // server 混入引号与换行：字段转义与成员清单转义都不许让 YAML 结构裂开
  const nasty = { proto: "trojan", server: 'evil"host\nline', port: 443,
                  ident: "pw", geo: "JP" };
  const Y = buildConfig(ACCESS, null, [nasty]).yaml;
  probe("注入 server 的引号/换行被转义进标量", Y.includes('server: "evil\\"host\\nline"'));
  probe("成员清单行走 JSON 引号转义", Y.includes('- "JP-evil\\"hostline"'));
  probe("注入节点的 name 字段同样被引住", Y.includes('name: "JP-evil\\"hostline"'));

  // ident 被流水线截断时，密码以 raw 的完整 userinfo 为准（100 位不缺斤短两）
  const longPw = "P".repeat(100);
  const clipped = { proto: "trojan", server: "9.9.9.9", port: 443,
                    ident: "truncated...", raw: `trojan://${longPw}@9.9.9.9:443` };
  const Y2 = buildConfig(ACCESS, null, [clipped]).yaml;
  probe("trojan 密码取 raw 完整 100 位", Y2.includes(`password: "${longPw}"`));

  const b64Auth = btoa(`aes-256-gcm:${longPw}`);
  const ssClip = { proto: "ss", server: "8.8.8.8", port: 8388,
                   ident: btoa("aes-256-gcm:cut"), raw: `ss://${b64Auth}@8.8.8.8:8388` };
  const Y3 = buildConfig(ACCESS, null, [ssClip]).yaml;
  probe("ss 密码取 raw 完整 100 位且 cipher 正确",
    Y3.includes('cipher: "aes-256-gcm"') && Y3.includes(`password: "${longPw}"`));

  // 控制字符清洗（线上实锤：某节点 alpn 混入 U+0096，Verge 严格解析器拒载
  // "invalid yaml"）。j() 统一剥 C0+C1 后，任何字段带脏字符渲染结果必须干净。
  const dirty = buildConfig(ACCESS, null, [{
    proto: "vless", server: "9.9.9.9", port: 443,
    ident: "u-xy", geo: "US",
    raw: "vless://u-xy@9.9.9.9:443?security=tls&alpn=dirty#t",
  }]).yaml;
  probe("C0/C1 控制字符混入字段被剥离（正文仅剩合法换行）",
    !/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]/.test(dirty));

  // top100 组测速间隔 180（60 是客户端 40 倍负担），WARP直连 300 不动；
  // 健康检查三件套（https+204 严格校验+快超时+失败3次强制重测）两组都必须在——
  // 治 MASQUE 底座 UDP 抖动下坏节点不被及时踢掉（线上 ERR_SSL_PROTOCOL_ERROR 实锤）
  const T = buildConfig(ACCESS, null,
    [{ proto: "vless", server: "1.2.3.4", port: 443, ident: "u1", geo: "JP" }]).yaml;
  probe("top100 组 interval 180",
    /- name: top100\n    type: url-test\n    url: [^\n]+\n    interval: 180/.test(T));
  probe("WARP直连 组 interval 300 不变",
    /- name: WARP直连\n    type: url-test\n    url: https:\/\/www\.gstatic\.com\/generate_204\n    interval: 300/.test(B));
  const CHEAT = /expected-status: 204\n    timeout: 5000\n    max-failed-times: 3/;
  probe("top100 组健康检查三件套", CHEAT.test(T) && /url: https:\/\/www\.gstatic\.com/.test(T));
  probe("WARP直连 组健康检查三件套", CHEAT.test(B) && !/http:\/\/www\.gstatic/.test(B));

  // DIRECT 三条规则集必须走 Clash/ 根路径（Clash/Ruleset/ 是 404 软返回）
  const urls = [...B.slice(B.indexOf("rule-providers:"), B.indexOf("\nrules:"))
    .matchAll(/^    url: (\S+)$/gm)].map((m) => m[1]);
  const directUrls = urls.filter((u) =>
    /LocalAreaNetwork|ChinaDomain|ChinaCompanyIp/.test(u));
  probe("DIRECT 规则集 3 条且都在 Clash/ 根路径",
    directUrls.length === 3 &&
    directUrls.every((u) => u.includes("/Clash/") && !u.includes("/Clash/Ruleset/")));
}

// ---- 场景七：加密 DNS（境内阿里 DoH 直连 / 境外 Cloudflare DoH 经 WARP 隧道）----
{
  const D = buildConfig(ACCESS, null, []).yaml;
  const dnsSeg = D.slice(D.indexOf("\ndns:"), D.indexOf("\nproxies:"));

  // 明文 UDP 53 必须彻底消失：DNS 段里任何"裸 IP 当服务器"的写法都是回魂
  probe("DNS 段无明文 UDP 53 服务器", !/^    - \d+\.\d+\.\d+\.\d+$/m.test(dnsSeg));
  probe("default-nameserver 已是加密 DNS",
    /default-nameserver:\n    - https:\/\/223\.5\.5\.5\/dns-query/.test(dnsSeg));
  probe("bootstrap 不再用 119.29.29.29", !dnsSeg.includes("119.29.29.29"));

  const nsSeg = dnsSeg.split("\n  nameserver:\n")[1].split("\n  proxy-server-nameserver:")[0];
  probe("nameserver 全部为 DoH",
    [...nsSeg.matchAll(/^    - (\S+)$/gm)].map((m) => m[1]).every((s) => s.startsWith("https://")));
  probe("proxy-server-nameserver 是境内加密 DNS（防鸡生蛋）",
    /proxy-server-nameserver:\n    - https:\/\/223\.5\.5\.5\/dns-query/.test(dnsSeg));

  // 境内 → 阿里云 DoH，直连（不带 #出口 后缀）
  const cnSeg = dnsSeg.split("'geosite:cn,private':")[1].split("'geosite:geolocation-!cn':")[0];
  probe("境内策略走阿里云加密 DNS", cnSeg.includes("https://223.5.5.5/dns-query"));
  probe("境内策略不经代理（无 #出口）", !cnSeg.includes("#"));

  // 境外 → Cloudflare DoH，且必须指定出口经 WARP 隧道（直连会被 RST + 结果被污染）
  const intlSeg = dnsSeg.split("'geosite:geolocation-!cn':")[1];
  probe("境外策略走 Cloudflare 加密 DNS",
    intlSeg.includes("https://1.1.1.1/dns-query") && intlSeg.includes("https://1.0.0.1/dns-query"));
  probe("境外 DNS 指定 WARP直连 出口",
    intlSeg.includes("https://1.1.1.1/dns-query#WARP直连"));
  probe("境外策略统一 Cloudflare（无 Google DoH）", !intlSeg.includes("8.8.8.8"));

  // masque 出站的隧道内 DNS 同样加密；IPv6 字面量必须带方括号
  probe("masque 隧道内 DNS 已改 DoH",
    /remote-dns-resolve: true\n    dns: \['https:\/\/1\.1\.1\.1\/dns-query', 'https:\/\/\[2606:4700:4700::1111\]\/dns-query'\]/.test(D));
  probe("masque 隧道内无裸 IP DNS 写法", !D.includes("dns: [1.1.1.1, 2606:4700:4700::1111]"));
}

console.log(`\n通过 ${hits} 失败 ${misses}`);
if (misses) process.exit(1);
