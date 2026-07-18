/**
 * CYBERWATCH — Tracker Worker
 * Reçoit les pageviews/clics depuis index.html (/track)
 * et sert les statistiques à admin.html (/stats), protégé par mot de passe.
 *
 * Déploiement : voir README-DEPLOY.md
 */

function corsHeaders(origin, allowedOrigin) {
  return {
    "Access-Control-Allow-Origin": origin === allowedOrigin ? origin : allowedOrigin,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
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

    // ---- GET /stats : renvoie les statistiques (protégé par mot de passe) ----
    if (url.pathname === "/stats" && request.method === "GET") {
      const auth = request.headers.get("Authorization") || "";
      if (auth !== `Bearer ${env.ADMIN_PASSWORD}`) {
        return new Response(JSON.stringify({ error: "unauthorized" }), {
          status: 401,
          headers: { ...headers, "Content-Type": "application/json" },
        });
      }

      const days = Number(url.searchParams.get("days") || 30);
      const since = new Date(Date.now() - days * 86400000).toISOString();

      const [totals, byPage, topClicks, byCountry, recent, uniqueVisitors] = await Promise.all([
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
      ]);

      return new Response(
        JSON.stringify({
          totals,
          unique_visitors: uniqueVisitors?.count || 0,
          by_page: byPage.results,
          top_clicks: topClicks.results,
          by_country: byCountry.results,
          recent: recent.results,
        }),
        { headers: { ...headers, "Content-Type": "application/json" } }
      );
    }

    return new Response("Not found", { status: 404, headers });
  },
};
