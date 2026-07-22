#!/usr/bin/env python3
"""
Met à jour data.json (section "attacks") en agrégeant plusieurs flux RSS de
médias spécialisés cybersécurité, puis en structurant chaque article par
RÈGLES (mots-clés), sans appel à une IA — 100% gratuit.

Sources utilisées :
  - BleepingComputer  (anglophone, très réactif sur les incidents)
  - The Hacker News   (anglophone, bonne couverture ransomware/APT)
  - LeMagIT           (francophone, couverture France/Europe)

Comment la structuration fonctionne (sans IA) :
  - "sector"  : détecté par correspondance de mots-clés dans titre+résumé
                (santé, finance, énergie, éducation, gouvernement...)
  - "actor"   : détecté par correspondance avec une liste de noms de groupes
                de ransomware/APT connus, mentionnés dans le texte
  - "sev"     : déduit de mots-clés de gravité (ex. "des millions", "critique",
                "zero-day" → critical/high), sinon "medium" par défaut
  - "desc"    : résumé RSS nettoyé (balises HTML retirées) et tronqué

⚠️ Limite assumée : une extraction par mots-clés est nécessairement moins
fine qu'une lecture humaine ou qu'un résumé par IA. Le "sector"/"actor"
resteront parfois "Non précisé" faute de correspondance évidente — c'est
préférable à inventer une information non fiable.

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from _dedupe import dedupe_articles

DATA_FILE = "data.json"
LOOKBACK_DAYS = 8
MAX_ROWS = 10

FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "LeMagIT", "url": "https://www.lemagit.fr/rss/feed.xml"},
    {"name": "LeMagIT", "url": "http://www.lemagit.fr/feed/all.xml"},  # repli si l'URL ci-dessus change
]

INCLUDE_KEYWORDS = [
    "ransomware", "breach", "hacked", "hack", "cyberattack", "cyber-attack",
    "attaque", "piratage", "fuite de données", "data leak", "compromised",
    "exploited", "exploited in the wild", "stolen data", "extorsion",
    "leaked", "incident", "compromis", "rançongiciel",
]

SEV_CRITICAL_KEYWORDS = ["million", "critical", "critique", "nation-state", "zero-day", "0-day"]
SEV_HIGH_KEYWORDS = ["breach", "exploited", "attack", "attaque", "piratage", "ransomware", "rançongiciel"]

SECTOR_KEYWORDS = {
    "Santé": ["hospital", "health", "santé", "hôpital", "patient", "medical"],
    "Finance": ["bank", "banque", "financial", "finance", "insurance", "assurance"],
    "Gouvernement": ["government", "gouvernement", "ministry", "ministère", "agency", "federal", "état"],
    "Éducation": ["university", "université", "school", "école", "student", "étudiant"],
    "Énergie": ["energy", "énergie", "power grid", "utility", "électrique", "pipeline"],
    "Manufacturing": ["manufacturing", "usine", "industrial", "industriel", "factory"],
    "Retail": ["retail", "commerce", "e-commerce", "magasin", "retailer"],
    "Télécoms": ["telecom", "télécom", "mobile carrier", "isp", "opérateur"],
    "Transport": ["airline", "airport", "aéroport", "railway", "transport", "logistics"],
    "Technologie": ["software company", "tech company", "saas", "cloud provider"],
}

KNOWN_ACTORS = [
    "Scattered Spider", "LockBit", "Akira", "Qilin", "Cl0p", "Clop", "BlackCat",
    "ALPHV", "Lynx", "INC Ransom", "RansomHub", "Play", "Medusa", "8Base",
    "BianLian", "Storm-2603", "Storm-0501", "Scattered Lapsus$ Hunters",
    "ShinyHunters", "World Leaks", "Fog", "Interlock", "The Gentlemen",
    "Phantom Mantis", "Anubis", "ANUBIS", "Warlock", "Rhysida", "Hunters International",
]


def fetch_url(url, timeout=20):
    req = urllib.request.Request(url, headers={"User-Agent": "cyberwatch-bot/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def strip_html(text):
    text = html.unescape(text or "")
    text = re.sub(r"<[^>]+>", " ", text)
    return re.sub(r"\s+", " ", text).strip()


def parse_rss(xml_bytes, source_name):
    items = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return items

    for item in root.findall(".//item"):
        title = item.findtext("title", "")
        link = item.findtext("link", "")
        desc = item.findtext("description", "") or item.findtext(
            "{http://purl.org/rss/1.0/modules/content/}encoded", "")
        pub = item.findtext("pubDate", "")
        items.append({"title": title, "link": link, "desc": desc, "pub": pub, "source": source_name})

    if not items:
        ns = {"a": "http://www.w3.org/2005/Atom"}
        for entry in root.findall(".//a:entry", ns):
            title = entry.findtext("a:title", "", ns)
            link_el = entry.find("a:link", ns)
            link = link_el.get("href") if link_el is not None else ""
            desc = entry.findtext("a:summary", "", ns)
            pub = entry.findtext("a:updated", "", ns)
            items.append({"title": title, "link": link, "desc": desc, "pub": pub, "source": source_name})

    return items


def detect_sector(text):
    low = text.lower()
    for sector, kws in SECTOR_KEYWORDS.items():
        if any(kw in low for kw in kws):
            return sector
    return "Non précisé"


def detect_actor(text):
    for actor in KNOWN_ACTORS:
        if actor.lower() in text.lower():
            return actor
    return "Non attribué"


def detect_severity(text):
    low = text.lower()
    if any(kw in low for kw in SEV_CRITICAL_KEYWORDS):
        return "critical"
    if any(kw in low for kw in SEV_HIGH_KEYWORDS):
        return "high"
    return "medium"


def is_relevant(text):
    low = text.lower()
    return any(kw in low for kw in INCLUDE_KEYWORDS)


def build_attacks():
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    seen_titles = set()
    seen_sources = set()
    all_items = []

    for feed in FEEDS:
        if feed["name"] in seen_sources and feed["name"] == "LeMagIT":
            continue
        try:
            raw = fetch_url(feed["url"])
        except Exception as e:
            print(f"[fetch_attacks] Flux indisponible ({feed['name']} — {feed['url']}) : {e}", file=sys.stderr)
            continue

        parsed = parse_rss(raw, feed["name"])
        if parsed:
            seen_sources.add(feed["name"])
        all_items.extend(parsed)

    # Même événement couvert par plusieurs sources → une seule fiche, pas une
    # par source.
    all_items = dedupe_articles(
        all_items,
        source_priority=["BleepingComputer", "The Hacker News", "LeMagIT"],
    )

    rows = []
    for it in all_items:
        title = strip_html(it["title"])
        if not title or title in seen_titles:
            continue

        desc_clean = strip_html(it["desc"])
        full_text = f"{title} {desc_clean}"

        if not is_relevant(full_text):
            continue

        try:
            pub_dt = parsedate_to_datetime(it["pub"])
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
        except Exception:
            pub_dt = None

        if pub_dt and pub_dt < cutoff:
            continue

        seen_titles.add(title)
        rows.append({
            "title": title,
            "sector": detect_sector(full_text),
            "date": pub_dt.strftime("%d %b %Y") if pub_dt else "",
            "actor": detect_actor(full_text),
            "sev": detect_severity(full_text),
            "desc": (desc_clean[:220] + "…") if len(desc_clean) > 220 else desc_clean,
            "src": it["source"],
            "url": it["link"],
            "_sort": pub_dt or cutoff,
        })

    rows.sort(key=lambda r: r["_sort"], reverse=True)
    for r in rows:
        del r["_sort"]
    return rows[:MAX_ROWS]


def main():
    new_attacks = build_attacks()

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if new_attacks:
        data["attacks"] = new_attacks
    else:
        print("[fetch_attacks] Aucun article pertinent trouvé — conservation des attaques précédentes.", file=sys.stderr)

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_attacks] {len(new_attacks)} attaque(s) mise(s) à jour depuis {len({r['src'] for r in new_attacks})} source(s).")


if __name__ == "__main__":
    main()
