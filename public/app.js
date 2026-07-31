const DNS_OPTIONS = {
  standard: "1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001",
  malware: "1.1.1.2, 1.0.0.2, 2606:4700:4700::1112, 2606:4700:4700::1002",
  family: "1.1.1.3, 1.0.0.3, 2606:4700:4700::1113, 2606:4700:4700::1003",
  none: "",
};

const form = document.querySelector("#generator-form");
const generateButton = document.querySelector("#generate-button");
const statusElement = document.querySelector("#status");
const resultElement = document.querySelector("#result");
const outputElement = document.querySelector("#config-output");
const accountInfoElement = document.querySelector("#account-info");
const copyButton = document.querySelector("#copy-button");
const downloadButton = document.querySelector("#download-button");

let latestConfig = "";

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!document.querySelector("#agree").checked) return;

  setBusy(true);
  setStatus("正在浏览器中生成 X25519 密钥…");

  try {
    const keys = await generateWireGuardKeys();
    setStatus("正在注册 Cloudflare WARP 设备…");

    const registration = await registerPublicKey(keys.publicKey);
    const config = buildConfig(keys.privateKey, registration);

    latestConfig = config;
    outputElement.value = config;
    renderMetadata(registration);
    resultElement.hidden = false;
    resultElement.scrollIntoView({ behavior: "smooth", block: "start" });

    downloadConfig(config);
    setStatus("配置已生成并开始下载。请妥善保存。", "success");
  } catch (error) {
    setStatus(error instanceof Error ? error.message : "生成失败", "error");
  } finally {
    setBusy(false);
  }
});

copyButton.addEventListener("click", async () => {
  if (!latestConfig) return;
  try {
    await navigator.clipboard.writeText(latestConfig);
    setStatus("配置已复制到剪贴板。", "success");
  } catch {
    outputElement.focus();
    outputElement.select();
    document.execCommand("copy");
    setStatus("配置已复制到剪贴板。", "success");
  }
});

downloadButton.addEventListener("click", () => {
  if (latestConfig) downloadConfig(latestConfig);
});

async function generateWireGuardKeys() {
  let keyPair;
  try {
    keyPair = await crypto.subtle.generateKey(
      { name: "X25519" },
      true,
      ["deriveBits"],
    );
  } catch {
    throw new Error("当前浏览器不支持 X25519 Web Crypto。请升级 Chrome、Edge、Firefox 或 Safari 后重试。");
  }

  const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);
  const publicBytes = new Uint8Array(
    await crypto.subtle.exportKey("raw", keyPair.publicKey),
  );

  if (!privateJwk.d || publicBytes.byteLength !== 32) {
    throw new Error("浏览器生成的 X25519 密钥格式不正确");
  }

  const privateBytes = base64UrlToBytes(privateJwk.d);
  if (privateBytes.byteLength !== 32) {
    throw new Error("浏览器生成的 X25519 私钥长度不正确");
  }

  return {
    privateKey: bytesToBase64(privateBytes),
    publicKey: bytesToBase64(publicBytes),
  };
}

async function registerPublicKey(publicKey) {
  const accessKey = document.querySelector("#access-key").value;
  const headers = { "Content-Type": "application/json" };
  if (accessKey) headers.Authorization = `Bearer ${accessKey}`;

  const response = await fetch("/api/register", {
    method: "POST",
    headers,
    cache: "no-store",
    body: JSON.stringify({
      publicKey,
      deviceName: document.querySelector("#device-name").value,
      model: document.querySelector("#model").value,
      locale: "en_US",
      teamsToken: document.querySelector("#teams-token").value,
    }),
  });

  const payload = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = payload?.detail ? `：${payload.detail}` : "";
    throw new Error(`${payload?.error || `注册失败，HTTP ${response.status}`}${detail}`);
  }
  return payload;
}

function buildConfig(privateKey, registration) {
  const endpointMode = document.querySelector("#endpoint-mode").value;
  const endpointValue = registration.endpoints?.[endpointMode];
  const endpoint = formatEndpoint(endpointValue, 2408);
  const dns = DNS_OPTIONS[document.querySelector("#dns-mode").value] || "";
  const mtu = clampInteger(document.querySelector("#mtu").value, 576, 1500, 1280);
  const keepalive = clampInteger(document.querySelector("#keepalive").value, 0, 65535, 25);

  if (!endpoint) {
    throw new Error(`Cloudflare 没有返回可用的 ${endpointMode} Endpoint`);
  }

  const lines = [
    "[Interface]",
    `PrivateKey = ${privateKey}`,
    `Address = ${withMask(registration.addresses.ipv4, 32)}, ${withMask(registration.addresses.ipv6, 128)}`,
  ];

  if (dns) lines.push(`DNS = ${dns}`);
  lines.push(`MTU = ${mtu}`);

  if (registration.deviceId) lines.push(`# CFDeviceId = ${registration.deviceId}`);
  if (registration.clientId) lines.push(`# CFClientId = ${registration.clientId}`);

  lines.push(
    "",
    "[Peer]",
    `PublicKey = ${registration.peerPublicKey}`,
    "AllowedIPs = 0.0.0.0/0, ::/0",
  );

  if (keepalive > 0) lines.push(`PersistentKeepalive = ${keepalive}`);
  lines.push(`Endpoint = ${endpoint}`, "");
  return lines.join("\n");
}

function withMask(address, bits) {
  if (!address) throw new Error("Cloudflare 没有返回接口地址");
  return address.includes("/") ? address : `${address}/${bits}`;
}

function formatEndpoint(value, defaultPort) {
  if (typeof value !== "string" || !value.trim()) return null;
  const endpoint = value.trim();

  if (/^\[[^\]]+\]:\d+$/.test(endpoint)) return endpoint;
  if (/^\[[^\]]+\]$/.test(endpoint)) return `${endpoint}:${defaultPort}`;

  const colonCount = (endpoint.match(/:/g) || []).length;
  if (colonCount === 0) return `${endpoint}:${defaultPort}`;
  if (colonCount === 1) {
    const lastPart = endpoint.slice(endpoint.lastIndexOf(":") + 1);
    return /^\d+$/.test(lastPart) ? endpoint : `${endpoint}:${defaultPort}`;
  }

  return `[${endpoint}]:${defaultPort}`;
}

function clampInteger(value, minimum, maximum, fallback) {
  const number = Number.parseInt(value, 10);
  if (!Number.isInteger(number)) return fallback;
  return Math.min(maximum, Math.max(minimum, number));
}

function base64UrlToBytes(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function bytesToBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function renderMetadata(registration) {
  const entries = [
    ["Device ID", registration.deviceId],
    ["Account ID", registration.account?.id],
    ["Account type", registration.account?.type],
    ["IPv4", registration.addresses?.ipv4],
    ["IPv6", registration.addresses?.ipv6],
  ].filter(([, value]) => value);

  accountInfoElement.replaceChildren();
  for (const [label, value] of entries) {
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    accountInfoElement.append(term, description);
  }
}

function downloadConfig(config) {
  const blob = new Blob([config], { type: "text/plain;charset=utf-8" });
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = "warp.conf";
  link.click();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
}

function setBusy(busy) {
  generateButton.disabled = busy;
  generateButton.textContent = busy ? "正在生成…" : "生成并下载 warp.conf";
}

function setStatus(message, type = "") {
  statusElement.textContent = message;
  statusElement.className = `status ${type}`.trim();
}
