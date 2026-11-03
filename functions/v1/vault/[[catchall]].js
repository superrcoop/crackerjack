/**
 * Cloudflare Pages Function: Ephemeral Secret Vault API
 * Handles:
 *   - POST /v1/vault       (Store zero-knowledge encrypted secret)
 *   - GET  /v1/vault/:id   (Fetch and self-destruct secret)
 *   - OPTIONS /v1/vault*   (CORS pre-flight)
 */

// Shared in-memory store across warm edge worker requests
const memoryVault = new Map();

function getCorsHeaders() {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Requested-With",
    "Content-Type": "application/json; charset=utf-8",
  };
}

function purgeExpired() {
  const now = Math.floor(Date.now() / 1000);
  for (const [id, rec] of memoryVault.entries()) {
    if (now >= rec.expires_at) {
      memoryVault.delete(id);
    }
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(),
  });
}

export async function onRequest(context) {
  const { request, params, env } = context;
  const url = new URL(request.url);
  const method = request.method.toUpperCase();

  if (method === "OPTIONS") {
    return new Response(null, { status: 204, headers: getCorsHeaders() });
  }

  purgeExpired();

  const pathParts = params.catchall || [];
  const secretId = pathParts.length > 0 ? pathParts[0] : "";

  // -------------------------------------------------------------------------
  // POST /v1/vault
  // -------------------------------------------------------------------------
  if (method === "POST") {
    try {
      const body = await request.json();
      const { id, ciphertext, expires_at, burn_on_read = true, allow_ip = null } = body;

      if (!id || !ciphertext || !expires_at) {
        return new Response(
          JSON.stringify({ error: "Missing required fields ('id', 'ciphertext', 'expires_at')." }),
          { status: 400, headers: getCorsHeaders() }
        );
      }

      const record = {
        id,
        ciphertext,
        expires_at: Number(expires_at),
        burn_on_read: Boolean(burn_on_read),
        allow_ip: allow_ip ? String(allow_ip).trim() : null,
        created_at: Math.floor(Date.now() / 1000),
      };

      memoryVault.set(id, record);

      // Support Cloudflare KV if bound to the Pages environment
      if (env && env.VAULT_KV) {
        try {
          const ttlSec = Math.max(60, record.expires_at - Math.floor(Date.now() / 1000));
          await env.VAULT_KV.put(id, JSON.stringify(record), { expirationTtl: ttlSec });
        } catch (e) {
          console.warn("KV put failed, retained in memory:", e);
        }
      }

      return new Response(
        JSON.stringify({
          id: record.id,
          expires_at: record.expires_at,
          burn_on_read: record.burn_on_read,
        }),
        { status: 201, headers: getCorsHeaders() }
      );
    } catch (err) {
      return new Response(
        JSON.stringify({ error: `Invalid request payload: ${err.message}` }),
        { status: 400, headers: getCorsHeaders() }
      );
    }
  }

  // -------------------------------------------------------------------------
  // GET /v1/vault/:id
  // -------------------------------------------------------------------------
  if (method === "GET") {
    if (!secretId) {
      return new Response(
        JSON.stringify({ error: "Missing secret ID in request path." }),
        { status: 400, headers: getCorsHeaders() }
      );
    }

    let record = memoryVault.get(secretId);

    // Check Cloudflare KV if available
    if (!record && env && env.VAULT_KV) {
      try {
        const raw = await env.VAULT_KV.get(secretId);
        if (raw) {
          record = JSON.parse(raw);
        }
      } catch (e) {
        console.warn("KV get failed:", e);
      }
    }

    const now = Math.floor(Date.now() / 1000);

    if (!record || now >= record.expires_at) {
      if (record) {
        memoryVault.delete(secretId);
        if (env && env.VAULT_KV) await env.VAULT_KV.delete(secretId).catch(() => {});
      }
      return new Response(
        JSON.stringify({ error: "Secret not found, expired, or already burned." }),
        { status: 404, headers: getCorsHeaders() }
      );
    }

    // IP Geofence validation
    const clientIp =
      request.headers.get("CF-Connecting-IP") ||
      request.headers.get("X-Forwarded-For")?.split(",")[0]?.trim() ||
      "";

    if (record.allow_ip) {
      const allowed = record.allow_ip.trim();
      const match = clientIp === allowed || (allowed.endsWith("*") && clientIp.startsWith(allowed.slice(0, -1)));
      if (!match) {
        return new Response(
          JSON.stringify({ error: `Access denied: Client IP '${clientIp}' is not authorized to decrypt this secret.` }),
          { status: 403, headers: getCorsHeaders() }
        );
      }
    }

    // Burn on read
    if (record.burn_on_read) {
      memoryVault.delete(secretId);
      if (env && env.VAULT_KV) {
        context.waitUntil(env.VAULT_KV.delete(secretId).catch(() => {}));
      }
    }

    return new Response(
      JSON.stringify({
        id: record.id,
        ciphertext: record.ciphertext,
        burn_on_read: record.burn_on_read,
        expires_at: record.expires_at,
      }),
      { status: 200, headers: getCorsHeaders() }
    );
  }

  return new Response(
    JSON.stringify({ error: `Method ${method} not allowed` }),
    { status: 405, headers: getCorsHeaders() }
  );
}
