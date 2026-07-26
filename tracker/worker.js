/**
 * CYBERWATCH — Tracker Worker
 * Reçoit les pageviews/clics depuis index.html (/track)
 * et sert les statistiques à admin.html (/stats), protégé par mot de passe.
 * Gère aussi le blocage manuel d'IP (/block, /unblock) depuis le dashboard.
 *
 * Déploiement : voir README-DEPLOY.md
 */

const MAX_ATTEMPTS = 3;
const LOCKOUT_MS = 60 * 60 * 1000; // 1h (bruteforce automatique)
const MANUAL_LOCK_UNTIL = "9999-12-31T23:59:59.000Z"; // "illimité" pour un blocage manuel

function corsHeaders(origin, allowedOriginsCsv) {
  const allowedOrigins = (allowedOriginsCsv || "").split(",").map(s => s.trim()).filter(Boolean);
  const matched = allowedOrigins.includes(origin);
  return {
    "Access-Control-Allow-Origin": matched ? origin : (allowedOrigins[0] || ""),
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

async function sha256Hex(text) {
  const enc = new TextEncoder().encode(text);
  const buf = await crypto.subtle.digest("SHA-256", enc);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function isPlausibleIp(ip) {
  // Vérification légère (pas une validation RFC complète) pour éviter les
  // entrées manifestement invalides dans le formulaire de blocage manuel.
  return /^[0-9a-fA-F:.]{3,45}$/.test(ip);
}

/**
 * Vérifie l'authentification admin, avec la même protection anti-bruteforce
 * (3 échecs -> 1h de blocage) sur TOUTES les routes protégées (/stats,
 * /block, /unblock) — pas seulement /stats — pour qu'on ne puisse pas
 * contourner le blocage en devinant le mot de passe via une autre route.
 *
 * Retourne { ok: true } si authentifié, ou { ok: false, response: Response }
 * si la requête doit être rejetée immédiatement.
 */
async function requireAdmin(request, env, headers) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const now = new Date();

  const attemptRow = await env.DB.prepare(
    "SELECT fail_count, locked_until, manual FROM login_attempts WHERE ip = ?"
  ).bind(ip).first();

  if (attemptRow && attemptRow.locked_until && new Date(attemptRow.locked_until) > now) {
    const isManual = !!attemptRow.manual;
    const message = isManual
      ? "Cette adresse IP a été bloquée manuellement."
      : `Trop de tentatives échouées. Réessaie dans ${Math.ceil((new Date(attemptRow.locked_until) - now) / 60000)} min.`;
    return {
      ok: false,
      response: new Response(JSON.stringify({ error: "locked", message, locked_until: attemptRow.locked_until }), {
        status: 429,
        headers: { ...headers, "Content-Type": "application/json" },
      }),
    };
  }

  const auth = request.headers.get("Authorization") || "";
  const expectedHash = await sha256Hex(env.ADMIN_PASSWORD);
  const isValid = auth === `Bearer ${expectedHash}`;

  if (!isValid) {
    const newCount = (attemptRow?.fail_count || 0) + 1;
    if (newCount >= MAX_ATTEMPTS) {
      const lockedUntil = new Date(now.getTime() + LOCKOUT_MS).toISOString();
      await env.DB.prepare(
        `INSERT INTO login_attempts (ip, fail_count, last_fail_at, locked_until, manual)
         VALUES (?, 0, ?, ?, 0)
         ON CONFLICT(ip) DO UPDATE SET fail_count = 0, last_fail_at = excluded.last_fail_at, locked_until = excluded.locked_until, manual = 0`
      ).bind(ip, now.toISOString(), lockedUntil).run();

      return {
        ok: false,
        response: new Response(JSON.stringify({
          error: "locked",
          message: "Trop de tentatives échouées. Compte bloqué 1h.",
          locked_until: lockedUntil,
        }), { status: 429, headers: { ...headers, "Content-Type": "application/json" } }),
      };
    }

    await env.DB.prepare(
      `INSERT INTO login_attempts (ip, fail_count, last_fail_at, locked_until, manual)
       VALUES (?, ?, ?, NULL, 0)
       ON CONFLICT(ip) DO UPDATE SET fail_count = excluded.fail_count, last_fail_at = excluded.last_fail_at`
    ).bind(ip, newCount, now.toISOString()).run();

    return {
      ok: false,
      response: new Response(JSON.stringify({
        error: "unauthorized",
        message: `Mot de passe incorrect. ${MAX_ATTEMPTS - newCount} essai(s) restant(s) avant blocage.`,
      }), { status: 401, headers: { ...headers, "Content-Type": "application/json" } }),
    };
  }

  // Connexion réussie : on efface l'historique d'échecs pour cette IP (sauf
  // si elle a un blocage manuel actif, mais dans ce cas on ne serait jamais
  // arrivés ici puisque le blocage est vérifié avant le mot de passe).
  if (attemptRow) {
    await env.DB.prepare("DELETE FROM login_attempts WHERE ip = ?").bind(ip).run();
  }

  return { ok: true };
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin") || "";
    const headers = corsHeaders(origin, env.ALLOWED_ORIGIN);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers });
    }

    // ---- POST /track : enregistre un événement (pageview ou clic) ----
    if (url.pathname === "/track" && request.method === "POST") {
      try {
        const body = await request.json();
        const ip = request.headers.get("CF-Connecting-IP") || "unknown";
        const country = request.cf?.country || null;
        const city = request.cf?.city || null;
        const ua = request.headers.get("User-Agent") || "";
        const ts = new Date().toISOString();

        await env.DB.prepare(
          `INSERT INTO events (ts, type, page, target, ip, country, city, referrer, user_agent, visitor_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
        )
          .bind(
            ts,
            body.type === "click" ? "click" : "pageview",
            body.page || null,
            body.target || null,
            ip,
            country,
            city,
            body.referrer || null,
            ua,
            body.visitor_id || null
          )
          .run();

        return new Response(JSON.stringify({ ok: true }), {
          headers: { ...headers, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...headers, "Content-Type": "application/json" },
        });
      }
    }

    // ---- POST /block : bloque manuellement une IP (illimité) ----
    if (url.pathname === "/block" && request.method === "POST") {
      const auth = await requireAdmin(request, env, headers);
      if (!auth.ok) return auth.response;

      try {
        const body = await request.json();
        const targetIp = (body.ip || "").trim();
        if (!isPlausibleIp(targetIp)) {
          return new Response(JSON.stringify({ error: "invalid_ip" }), {
            status: 400,
            headers: { ...headers, "Content-Type": "application/json" },
          });
        }

        await env.DB.prepare(
          `INSERT INTO login_attempts (ip, fail_count, last_fail_at, locked_until, manual)
           VALUES (?, 0, ?, ?, 1)
           ON CONFLICT(ip) DO UPDATE SET locked_until = excluded.locked_until, manual = 1`
        ).bind(targetIp, new Date().toISOString(), MANUAL_LOCK_UNTIL).run();

        return new Response(JSON.stringify({ ok: true, ip: targetIp }), {
          headers: { ...headers, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...headers, "Content-Type": "application/json" },
        });
      }
    }

    // ---- POST /unblock : débloque une IP (manuelle ou bruteforce) ----
    if (url.pathname === "/unblock" && request.method === "POST") {
      const auth = await requireAdmin(request, env, headers);
      if (!auth.ok) return auth.response;

      try {
        const body = await request.json();
        const targetIp = (body.ip || "").trim();
        if (!isPlausibleIp(targetIp)) {
          return new Response(JSON.stringify({ error: "invalid_ip" }), {
            status: 400,
            headers: { ...headers, "Content-Type": "application/json" },
          });
        }

        await env.DB.prepare("DELETE FROM login_attempts WHERE ip = ?").bind(targetIp).run();

        return new Response(JSON.stringify({ ok: true, ip: targetIp }), {
          headers: { ...headers, "Content-Type": "application/json" },
        });
      } catch (e) {
        return new Response(JSON.stringify({ ok: false, error: String(e) }), {
          status: 500,
          headers: { ...headers, "Content-Type": "application/json" },
        });
      }
    }

    // ---- GET /stats : renvoie les statistiques (protégé par mot de passe,
    //      avec blocage après 3 échecs pendant 1h, ou blocage manuel) ----
    if (url.pathname === "/stats" && request.method === "GET") {
      const auth = await requireAdmin(request, env, headers);
      if (!auth.ok) return auth.response;

      const days = Number(url.searchParams.get("days") || 30);
      const since = new Date(Date.now() - days * 86400000).toISOString();
      const now = new Date();

      const sinceWeek = new Date(Date.now() - 7 * 86400000).toISOString();
      const sinceMonth = new Date(Date.now() - 30 * 86400000).toISOString();
      const sinceYear = new Date(Date.now() - 365 * 86400000).toISOString();

      const [totals, byPage, topClicks, byCountry, recent, uniqueVisitors,
             weekTotal, monthTotal, yearTotal, allTimeTotal,
             lockedIps, recentAttempts] = await Promise.all([
        env.DB.prepare(
          `SELECT
             SUM(CASE WHEN type='pageview' THEN 1 ELSE 0 END) as pageviews,
             SUM(CASE WHEN type='click' THEN 1 ELSE 0 END) as clicks
           FROM events WHERE ts >= ?`
        ).bind(since).first(),

        env.DB.prepare(
          `SELECT page, COUNT(*) as count FROM events
           WHERE type='pageview' AND ts >= ? GROUP BY page ORDER BY count DESC LIMIT 20`
        ).bind(since).all(),

        env.DB.prepare(
          `SELECT target, COUNT(*) as count FROM events
           WHERE type='click' AND ts >= ? GROUP BY target ORDER BY count DESC LIMIT 20`
        ).bind(since).all(),

        env.DB.prepare(
          `SELECT country, COUNT(DISTINCT visitor_id) as count FROM events
           WHERE ts >= ? AND country IS NOT NULL GROUP BY country ORDER BY count DESC LIMIT 15`
        ).bind(since).all(),

        env.DB.prepare(
          `SELECT ts, type, page, target, ip, country, city, referrer, visitor_id FROM events
           WHERE ts >= ? ORDER BY ts DESC LIMIT 200`
        ).bind(since).all(),

        env.DB.prepare(
          `SELECT COUNT(DISTINCT visitor_id) as count FROM events WHERE ts >= ?`
        ).bind(since).first(),

        env.DB.prepare(
          `SELECT COUNT(*) as count FROM events WHERE type='pageview' AND ts >= ?`
        ).bind(sinceWeek).first(),

        env.DB.prepare(
          `SELECT COUNT(*) as count FROM events WHERE type='pageview' AND ts >= ?`
        ).bind(sinceMonth).first(),

        env.DB.prepare(
          `SELECT COUNT(*) as count FROM events WHERE type='pageview' AND ts >= ?`
        ).bind(sinceYear).first(),

        env.DB.prepare(
          `SELECT COUNT(*) as count FROM events WHERE type='pageview'`
        ).first(),

        env.DB.prepare(
          `SELECT ip, fail_count, last_fail_at, locked_until, manual FROM login_attempts
           WHERE locked_until IS NOT NULL AND locked_until > ?
           ORDER BY manual DESC, locked_until DESC`
        ).bind(now.toISOString()).all(),

        env.DB.prepare(
          `SELECT ip, fail_count, last_fail_at, locked_until, manual FROM login_attempts
           ORDER BY last_fail_at DESC LIMIT 50`
        ).all(),
      ]);

      return new Response(
        JSON.stringify({
          totals,
          unique_visitors: uniqueVisitors?.count || 0,
          by_page: byPage.results,
          top_clicks: topClicks.results,
          by_country: byCountry.results,
          recent: recent.results,
          period_totals: {
            week: weekTotal?.count || 0,
            month: monthTotal?.count || 0,
            year: yearTotal?.count || 0,
            all_time: allTimeTotal?.count || 0,
          },
          security: {
            locked_ips: lockedIps.results,
            recent_attempts: recentAttempts.results,
          },
        }),
        { headers: { ...headers, "Content-Type": "application/json" } }
      );
    }

    return new Response("Not found", { status: 404, headers });
  },
};
