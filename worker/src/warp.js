// Cloudflare WARP 设备注册 + MASQUE 公钥下发。
// 只依赖 fetch 与 WebCrypto，Workers 运行时原生可用。
const GATEWAY = "https://api.cloudflareclient.com/v0a4471";
const HEADERS = {
  "User-Agent": "WARP for Android",
  "CF-Client-Version": "a-6.35-4471",
  "Content-Type": "application/json; charset=UTF-8",
};

const toBase64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));

/** n 字节随机数 → base64（注册用的临时密钥）。 */
function randomB64(n) {
  return toBase64(crypto.getRandomValues(new Uint8Array(n)));
}

/** n 字节随机数 → 十六进制（设备序列号）。 */
function randomHex(n) {
  const raw = crypto.getRandomValues(new Uint8Array(n));
  let out = "";
  for (const byte of raw) out += byte.toString(16).padStart(2, "0");
  return out;
}

// WireGuard 侧的时间戳要 Go 的布局 "2006-01-02T15:04:05.000-07:00"
function gatewayClock() {
  return new Date().toISOString().replace("Z", "+00:00");
}

/** WARP 注册档案的可用性：四个关键字段缺一即失效。
 *  设备残缺时拿去生成配置，要么握手失败要么 v6 地址缺失，不如重注册。 */
export function warpUsable(cached) {
  const need = ["privateKey", "peerPublicKey", "ipv4", "ipv6"];
  return !!cached && need.every((f) => !!cached[f]);
}

/**
 * 开一台新设备并把 MASQUE 公钥挂上去。
 * 成功返回 { deviceId, token, privateKey, peerPublicKey, ipv4, ipv6, registeredAt }。
 */
export async function enrollWarpDevice(deviceName = "cf-worker") {
  // 第一步：换一张 WireGuard 临时身份证
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
      locale: "en-US",
    }),
  });
  if (!enroll.ok) {
    const detail = (await enroll.text()).slice(0, 200);
    throw new Error(`WARP 开户失败 ${enroll.status}: ${detail}`);
  }
  const card = await enroll.json();

  // 第二步：另起一对 P-256 密钥——MASQUE 的加密体系与 WireGuard 不通用
  const pair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const publicSpki = toBase64(await crypto.subtle.exportKey("spki", pair.publicKey));
  const privatePkcs8 = toBase64(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  // mihomo 认 SEC1，WebCrypto 只吐 PKCS8，中间要转一次格式
  const privateSec1 = sec1FromPkcs8(privatePkcs8);

  const upgrade = await fetch(`${GATEWAY}/reg/${card.id}`, {
    method: "PATCH",
    headers: { ...HEADERS, Authorization: `Bearer ${card.token}` },
    body: JSON.stringify({
      key: publicSpki,
      key_type: "secp256r1",
      tunnel_type: "masque",
      name: deviceName,
    }),
  });
  if (!upgrade.ok) {
    const detail = (await upgrade.text()).slice(0, 200);
    throw new Error(`MASQUE 挂载失败 ${upgrade.status}: ${detail}`);
  }
  const tuned = await upgrade.json();

  // 对端公钥可能带 PEM 壳，mihomo 只吃壳里那串裸 base64
  const wrapped = tuned.config?.peers?.[0]?.public_key || "";
  const barePeer = wrapped.includes("-----")
    ? wrapped.split("\n").filter((line) => line && !line.startsWith("-----")).join("")
    : wrapped;

  return {
    deviceId: card.id,
    token: card.token,
    privateKey: privateSec1,
    peerPublicKey: barePeer,
    ipv4: tuned.config?.interface?.addresses?.v4 || card.config?.interface?.addresses?.v4,
    ipv6: tuned.config?.interface?.addresses?.v6 || card.config?.interface?.addresses?.v6,
    registeredAt: new Date().toISOString(),
  };
}

// ---- PKCS8 → SEC1(RFC 5915) 换装 ----
//
// mihomo 直接喂 PKCS8 会报 "use ParsePKCS8PrivateKey instead"，而 WebCrypto
// 又只会导出 PKCS8，所以这里手工重排 DER。注意两层坑：
//   1) 只抠出 PKCS8 里内嵌的 OCTET STRING 还不够——WebCrypto 生成的内层
//      SEC1 把曲线参数省略了（在外层 AlgorithmIdentifier 里），mihomo 会报
//      "unknown elliptic curve"；
//   2) 因此要重新编码一份带 [0] namedCurve 的完整 SEC1：
//      SEQUENCE { INTEGER 1, OCTET STRING 私钥(32B),
//                 [0] OID 1.2.840.10045.3.1.7, [1] BIT STRING 公钥 }

/** 读一个 DER TLV，返回 [标签, 值起点, 值长度, 下一个 TLV 起点]。 */
function readTlv(bytes, at) {
  const tag = bytes[at];
  let size = bytes[at + 1];
  let body = at + 2;
  if (size & 0x80) {
    const wide = size & 0x7f;
    size = 0;
    for (let k = 0; k < wide; k++) size = (size << 8) | bytes[body + k];
    body += wide;
  }
  return [tag, body, size, body + size];
}

/** DER 长度字段编码。 */
function encodeLength(n) {
  if (n < 0x80) return [n];
  if (n < 0x100) return [0x81, n];
  return [0x82, n >> 8, n & 0xff];
}

export function sec1FromPkcs8(base64Pkcs8) {
  const der = Uint8Array.from(atob(base64Pkcs8), (ch) => ch.charCodeAt(0));

  // 自外向内：外层 SEQUENCE → version → AlgorithmIdentifier → 私钥 OCTET STRING
  let cursor = readTlv(der, 0)[1];
  cursor = readTlv(der, cursor)[3];
  cursor = readTlv(der, cursor)[3];
  const [outerTag, outerStart, outerLen] = readTlv(der, cursor);
  if (outerTag !== 0x04) throw new Error("PKCS8 结构不符合预期");

  // 内层是一段独立 DER（可能自带曲线参数，也可能没有），单独解析
  const shell = der.subarray(outerStart, outerStart + outerLen);
  let walk = readTlv(shell, 0)[1];
  walk = readTlv(shell, walk)[3];                       // 跳过 version
  const [keyTag, keyStart, keyLen] = readTlv(shell, walk);  // privateKey
  if (keyTag !== 0x04) throw new Error("SEC1 结构不符合预期");
  const secret = shell.subarray(keyStart, keyStart + keyLen);

  // prime256v1 的 OID 编码：1.2.840.10045.3.1.7
  const CURVE_OID = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
  const payload = [
    0x02, 0x01, 0x01,                          // version = 1
    0x04, secret.length, ...secret,            // 私钥本体
    0xa0, CURVE_OID.length, ...CURVE_OID,      // [0] namedCurve
  ];
  const frame = [0x30, ...encodeLength(payload.length), ...payload];
  return btoa(String.fromCharCode(...frame));
}
