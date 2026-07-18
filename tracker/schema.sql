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
