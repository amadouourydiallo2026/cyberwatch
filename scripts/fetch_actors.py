#!/usr/bin/env python3
"""
Met à jour data.json (section "actors") en détectant, dans plusieurs flux RSS
de médias/labos de sécurité crédibles, les threat actors les plus mentionnés
récemment — avec un résumé et un lien vers l'article source. 100% gratuit,
sans IA (détection par correspondance de nom).

Sources utilisées :
  - BleepingComputer            (actualité générale incidents/ransomware)
  - The Hacker News             (actualité générale, bonne couverture APT)
  - LeMagIT                     (francophone, France/Europe)
  - Cisco Talos                 (recherche threat intel, très crédible)
  - Microsoft Security Blog     (recherche threat intel, très crédible)

Comment ça fonctionne (sans IA) :
  - Chaque article des 14 derniers jours est scanné à la recherche d'un nom
    de groupe connu (liste KNOWN_ACTORS ci-dessous).
  - Pour chaque groupe trouvé, on garde l'article le plus RÉCENT le
    mentionnant comme résumé + source, et on compte le nombre total de
    mentions sur la période pour le classement.
  - Les 9 groupes les plus mentionnés sont retenus.

⚠️ Limites assumées :
  - Un groupe non présent dans KNOWN_ACTORS ne sera jamais détecté. La liste
    devra être mise à jour à la main de temps en temps (nouveaux groupes).
  - "Le plus mentionné" ≠ "le plus dangereux" : c'est un indicateur de
    couverture médiatique, pas une évaluation de risque.
  - Le champ JSON "victims" est réutilisé pour indiquer le nombre de
    mentions récentes (et non un nombre de victimes réelles) — à ajuster
    dans index.html si l'intitulé affiché prête à confusion.

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime

from _dedupe import dedupe_articles

DATA_FILE = "data.json"
LOOKBACK_DAYS = 14
MAX_ROWS = 9

FEEDS = [
    {"name": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/"},
    {"name": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"name": "LeMagIT", "url": "https://www.lemagit.fr/rss/feed.xml"},
    {"name": "LeMagIT", "url": "http://www.lemagit.fr/feed/all.xml"},  # repli
    {"name": "Cisco Talos", "url": "http://feeds.feedburner.com/feedburner/Talos"},
    {"name": "Microsoft Security Blog", "url": "https://www.microsoft.com/en-us/security/blog/feed/"},
]

# Groupes de ransomware / extorsion connus
RANSOMWARE_ACTORS = [
    "Scattered Spider", "LockBit", "Akira", "Qilin", "Cl0p", "Clop", "BlackCat",
    "ALPHV", "Lynx", "INC Ransom", "RansomHub", "Play", "Medusa", "8Base",
    "BianLian", "ShinyHunters", "World Leaks", "Fog", "Interlock",
    "The Gentlemen", "Phantom Mantis", "Anubis", "ANUBIS", "Warlock",
    "Rhysida", "Hunters International", "DragonForce", "SafePay",
]

# Groupes APT / espionnage étatique connus (désignations courantes)
APT_ACTORS = [
    "Storm-2603", "Storm-0501", "Storm-1567", "Volt Typhoon", "Salt Typhoon",
    "APT28", "APT29", "Lazarus", "Kimsuky", "Sandworm", "Fancy Bear",
    "Cozy Bear", "Mustang Panda", "UAT-7810", "UNC3944", "UNC2165",
]

KNOWN_ACTORS = RANSOMWARE_ACTORS + APT_ACTORS


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


def actor_type(name):
    if name in APT_ACTORS:
        return "APT / Espionnage"
    return "RaaS / Extorsion"


def build_actors():
    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    seen_sources = set()
    all_items = []

    for feed in FEEDS:
        if feed["name"] in seen_sources and feed["name"] == "LeMagIT":
            continue
        try:
            raw = fetch_url(feed["url"])
        except Exception as e:
            print(f"[fetch_actors] Flux indisponible ({feed['name']} — {feed['url']}) : {e}", file=sys.stderr)
            continue

        parsed = parse_rss(raw, feed["name"])
        if parsed:
            seen_sources.add(feed["name"])
        all_items.extend(parsed)

    # Un même événement couvert par plusieurs sources ne doit compter qu'une
    # seule fois — sinon un groupe cité dans 2 articles sur le même incident
    # serait injustement mieux classé qu'un groupe cité une seule fois pour
    # un incident distinct.
    all_items = dedupe_articles(
        all_items,
        source_priority=["Cisco Talos", "Microsoft Security Blog", "BleepingComputer", "The Hacker News", "LeMagIT"],
    )

    mention_count = defaultdict(int)
    best_article = {}  # actor -> (pub_dt, article_info)

    for it in all_items:
        title = strip_html(it["title"])
        desc_clean = strip_html(it["desc"])
        full_text = f"{title} {desc_clean}"

        try:
            pub_dt = parsedate_to_datetime(it["pub"])
            if pub_dt.tzinfo is None:
                pub_dt = pub_dt.replace(tzinfo=timezone.utc)
        except Exception:
            pub_dt = None

        if pub_dt and pub_dt < cutoff:
            continue

        for actor in KNOWN_ACTORS:
            if actor.lower() in full_text.lower():
                mention_count[actor] += 1
                current_best = best_article.get(actor)
                sort_key = pub_dt or cutoff
                if current_best is None or sort_key > current_best[0]:
                    best_article[actor] = (sort_key, {
                        "title": title,
                        "desc": desc_clean,
                        "url": it["link"],
                        "src": it["source"],
                        "date": pub_dt.strftime("%d %b %Y") if pub_dt else "",
                    })

    ranked = sorted(mention_count.items(), key=lambda x: x[1], reverse=True)[:MAX_ROWS]

    rows = []
    for actor, count in ranked:
        art = best_article[actor][1]
        rows.append({
            "name": actor,
            "type": actor_type(actor),
            "desc": (art["desc"][:220] + "…") if len(art["desc"]) > 220 else art["desc"],
            "victims": f"{count} mention(s) récente(s) — dernier article : {art['date']}",
            "region": "Non précisé",
            "url": art["url"],
            "src": art["src"],
        })
    return rows


def main():
    new_actors = build_actors()

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    if new_actors:
        data["actors"] = new_actors
    else:
        print("[fetch_actors] Aucun groupe connu détecté dans les flux — conservation des acteurs précédents.", file=sys.stderr)

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_actors] {len(new_actors)} acteur(s) mis à jour depuis {len({r['src'] for r in new_actors})} source(s).")


if __name__ == "__main__":
    main()
