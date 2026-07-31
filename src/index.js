const WARP_API = "https://api.cloudflareclient.com/v0a2483/reg";
const MAX_BODY_BYTES = 24 * 1024;

const BASE_HEADERS = {
  "Cache-Control": "no-store, max-age=0",
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Referrer-Policy": "no-referrer",
  "X-Content-Type-Options": "nosniff",
};

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/register") {
      return handleRegister(request, env);
    }

    if (url.pathname.startsWith("/api/")) {
      return jsonResponse({ error: "Not found" }, 404);
    }

    return env.ASSETS.fetch(request);
  },
};

async function handleRegister(request, env) {
  if (request.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405, {
      Allow: "POST",
    });
  }

  if (!(await isAuthorized(request, env.ACCESS_KEY))) {
    return jsonResponse({ error: "Access key is invalid" }, 401, {
      "WWW-Authenticate": 'Bearer realm="WARP config generator"',
    });
  }

  const contentType = request.headers.get("content-type") || "";
  if (!contentType.toLowerCase().includes("application/json")) {
    return jsonResponse({ error: "Content-Type must be application/json" }, 415);
  }

  const declaredLength = Number(request.headers.get("content-length") || 0);
  if (declaredLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: "Request body is too large" }, 413);
  }

  let rawBody;
  try {
    rawBody = await request.text();
  } catch {
    return jsonResponse({ error: "Unable to read request body" }, 400);
  }

  if (new TextEncoder().encode(rawBody).byteLength > MAX_BODY_BYTES) {
    return jsonResponse({ error: "Request body is too large" }, 413);
  }

  let input;
  try {
    input = JSON.parse(rawBody);
  } catch {
    return jsonResponse({ error: "Request body is not valid JSON" }, 400);
  }

  const validation = validateInput(input);
  if (!validation.ok) {
    return jsonResponse({ error: validation.error }, 400);
  }

  const headers = new Headers({
    Accept: "application/json; charset=UTF-8",
    "Content-Type": "application/json",
    "CF-Client-Version": "a-6.81-2410012252.0",
    "User-Agent": "1.1.1.1/6.81",
  });

  if (validation.value.teamsToken) {
    headers.set("CF-Access-Jwt-Assertion", validation.value.teamsToken);
  }

  let upstream;
  try {
    upstream = await fetch(WARP_API, {
      method: "POST",
      headers,
      body: JSON.stringify({
        key: validation.value.publicKey,
        install_id: "",
        fcm_token: "",
        model: validation.value.model,
        serial_number: "",
        name: validation.value.deviceName,
        locale: validation.value.locale,
      }),
      redirect: "error",
    });
  } catch (error) {
    return jsonResponse(
      {
        error: "Cloudflare WARP registration request failed",
        detail: safeErrorMessage(error),
      },
      502,
    );
  }

  const upstreamText = await upstream.text();
  let upstreamData;
  try {
    upstreamData = JSON.parse(upstreamText);
  } catch {
    upstreamData = null;
  }

  if (!upstream.ok) {
    return jsonResponse(
      {
        error: `Cloudflare WARP registration returned HTTP ${upstream.status}`,
        detail: extractUpstreamError(upstreamData),
      },
      502,
    );
  }

  let result;
  try {
    result = normalizeRegistration(upstreamData);
  } catch (error) {
    return jsonResponse(
      {
        error: "Cloudflare returned an unexpected response format",
        detail: safeErrorMessage(error),
      },
      502,
    );
  }

  return jsonResponse(result, 200);
}

function validateInput(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    return { ok: false, error: "Request body must be a JSON object" };
  }

  const publicKey = cleanString(input.publicKey, 64);
  if (!publicKey || !isWireGuardPublicKey(publicKey)) {
    return { ok: false, error: "publicKey must be a 32-byte Base64 key" };
  }

  const deviceName = cleanString(input.deviceName, 128) ?? "";
  const model = cleanString(input.model, 128) || "warp-worker-generator";
  const locale = cleanString(input.locale, 16) || "en_US";
  const teamsToken = cleanString(input.teamsToken, 16384) ?? "";

  if (!/^[A-Za-z]{2}(?:[_-][A-Za-z]{2})?$/.test(locale)) {
    return { ok: false, error: "locale must look like en_US" };
  }

  return {
    ok: true,
    value: { publicKey, deviceName, model, locale, teamsToken },
  };
}

function cleanString(value, maxLength) {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") return null;
  const cleaned = value.trim();
  if (cleaned.length > maxLength) return null;
  return cleaned;
}

function isWireGuardPublicKey(value) {
  try {
    const bytes = base64ToBytes(value);
    return bytes.byteLength === 32;
  } catch {
    return false;
  }
}

function base64ToBytes(value) {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    throw new Error("Invalid Base64");
  }
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

async function isAuthorized(request, configuredKey) {
  if (!configuredKey) return true;

  const authorization = request.headers.get("authorization") || "";
  const expected = `Bearer ${configuredKey}`;
  const encoder = new TextEncoder();
  const suppliedBytes = encoder.encode(authorization);
  const expectedBytes = encoder.encode(expected);

  if (suppliedBytes.byteLength !== expectedBytes.byteLength) {
    return false;
  }

  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(suppliedBytes, expectedBytes);
  }

  let difference = 0;
  for (let index = 0; index < suppliedBytes.length; index += 1) {
    difference |= suppliedBytes[index] ^ expectedBytes[index];
  }
  return difference === 0;
}

export function normalizeRegistration(data) {
  if (!data || typeof data !== "object") {
    throw new Error("Registration response is empty");
  }

  const config = data.config;
  const peer = config?.peers?.[0];
  const endpoint = peer?.endpoint;
  const addresses = config?.interface?.addresses;

  const peerPublicKey = requireString(peer?.public_key, "peer public key");
  const ipv4Address = requireString(addresses?.v4, "IPv4 address");
  const ipv6Address = requireString(addresses?.v6, "IPv6 address");

  if (!endpoint?.v4 && !endpoint?.host && !endpoint?.v6) {
    throw new Error("No WARP endpoint was returned");
  }

  return {
    peerPublicKey,
    addresses: {
      ipv4: ipv4Address,
      ipv6: ipv6Address,
    },
    endpoints: {
      ipv4: optionalString(endpoint.v4),
      ipv6: optionalString(endpoint.v6),
      hostname: optionalString(endpoint.host),
    },
    clientId: optionalString(config?.client_id),
    deviceId: optionalString(data.id),
    account: {
      id: optionalString(data.account?.id),
      type: optionalString(data.account?.account_type || data.account?.type),
      license: optionalString(data.account?.license),
    },
  };
}

function requireString(value, label) {
  const result = optionalString(value);
  if (!result) throw new Error(`Missing ${label}`);
  return result;
}

function optionalString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function extractUpstreamError(data) {
  if (!data || typeof data !== "object") return null;

  const candidates = [
    data.message,
    data.error,
    data.errors?.[0]?.message,
    data.errors?.[0]?.detail,
  ];

  for (const candidate of candidates) {
    if (typeof candidate === "string" && candidate.trim()) {
      return candidate.trim().slice(0, 500);
    }
  }
  return null;
}

function safeErrorMessage(error) {
  if (error instanceof Error && error.message) {
    return error.message.slice(0, 500);
  }
  return "Unknown error";
}

function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...BASE_HEADERS,
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}
