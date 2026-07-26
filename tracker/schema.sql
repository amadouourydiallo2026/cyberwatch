-- Table des événements (pageviews + clics)
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,              -- timestamp ISO
  type TEXT NOT NULL,            -- 'pageview' ou 'click'
  page TEXT,                     -- chemin de la page
  target TEXT,                   -- id/texte de l'élément cliqué (si type=click)
  ip TEXT,                       -- adresse IP du visiteur
  country TEXT,                  -- pays (déduit par Cloudflare, gratuit)
  city TEXT,
  referrer TEXT,
  user_agent TEXT,
  visitor_id TEXT                -- identifiant anonyme (cookie léger, pas de PII)
);

CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_visitor ON events(visitor_id);

-- Suivi des tentatives de connexion admin par IP, pour le blocage après
-- échecs répétés (3 essais -> 1h de blocage), et pour le blocage manuel
-- (illimité dans le temps, déclenché depuis le dashboard).
CREATE TABLE IF NOT EXISTS login_attempts (
  ip TEXT PRIMARY KEY,
  fail_count INTEGER NOT NULL DEFAULT 0,
  last_fail_at TEXT,
  locked_until TEXT,
  manual INTEGER NOT NULL DEFAULT 0   -- 1 = bloqué manuellement (pas par bruteforce)
);
