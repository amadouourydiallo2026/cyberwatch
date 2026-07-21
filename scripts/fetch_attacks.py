#!/usr/bin/env python3
"""
Met à jour data.json (section "attacks") avec les cyberattaques les plus
récentes issues de l'API publique et gratuite Ransomware.live.

⚠️ Limite importante : Ransomware.live ne couvre que les attaques liées à des
groupes de ransomware/extorsion (basées sur leurs sites de fuite publics).
Les attaques de sabotage, d'espionnage étatique, ou sans revendication
ransomware (ex. incident purement DDoS) n'apparaîtront jamais ici. Il n'existe
pas de flux public gratuit unique couvrant "toutes les cyberattaques".

API : https://api.ransomware.live/v2 (aucune clé requise, mais rate-limitée)

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

API_BASE = "https://api.ransomware.live/v2"
DATA_FILE = "data.json"
LOOKBACK_DAYS = 10   # fenêtre large : les attaques "les plus commentées" ne
                      # sont pas forcément celles d'hier
MAX_ROWS = 10

SEV_BY_RANK = ["critical", "critical", "high", "high", "high",
               "medium", "medium", "medium", "medium", "medium"]


def fetch_json(url):
    req = urllib.request.Request(url, headers={"User-Agent": "cyberwatch-bot/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def build_attacks():
    items = fetch_json(f"{API_BASE}/recentcyberattacks")
    if not isinstance(items, list):
        # Certaines réponses de l'API sont enveloppées dans un objet
        items = items.get("data", []) if isinstance(items, dict) else []

    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    parsed = []
    for item in items:
        date_str = item.get("attackdate") or item.get("date") or item.get("published") or ""
        try:
            d = datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            d = None
        if d and d < cutoff:
            continue
        parsed.append((d or cutoff, item))

    parsed.sort(key=lambda x: x[0], reverse=True)
    selected = parsed[:MAX_ROWS]

    rows = []
    for i, (d, item) in enumerate(selected):
        victim = item.get("victim") or item.get("title") or "Victime non identifiée"
        group = item.get("group") or "Non attribué"
        country = item.get("country") or ""
        sector = item.get("activity") or item.get("sector") or ""
        press = item.get("press") or []
        src_url = ""
        src_name = "Ransomware.live"
        if isinstance(press, list) and press:
            first = press[0]
            if isinstance(first, dict):
                src_url = first.get("link", "") or first.get("url", "")
                src_name = first.get("source", "Ransomware.live")
            elif isinstance(first, str):
                src_url = first

        rows.append({
            "title": victim,
            "sector": sector if sector else (country or "Non précisé"),
            "date": d.strftime("%d %b %Y") if d else "",
            "actor": group,
            "sev": SEV_BY_RANK[i] if i < len(SEV_BY_RANK) else "medium",
            "desc": f"Attaque revendiquée par {group}" + (f", secteur {sector}" if sector else "") + ".",
            "src": src_name,
            "url": src_url or f"https://www.ransomware.live/group/{group}",
        })
    return rows


def main():
    try:
        new_attacks = build_attacks()
    except Exception as e:
        print(f"[fetch_attacks] Échec de récupération de Ransomware.live : {e}", file=sys.stderr)
        sys.exit(1)

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if new_attacks:
        data["attacks"] = new_attacks
    # Si l'API échoue ou est vide, on conserve les entrées précédentes.

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_attacks] {len(new_attacks)} attaque(s) mise(s) à jour depuis Ransomware.live.")


if __name__ == "__main__":
    main()
