#!/usr/bin/env python3
"""
Met à jour data.json avec les 12 à 20 vulnérabilités les plus récentes du
catalogue CISA KEV (Known Exploited Vulnerabilities), classées par date
d'ajout décroissante.

Ne touche PAS aux sections "attacks", "actors", "threats" : il n'existe pas
de flux public unique et structuré équivalent pour ces catégories. Elles
restent éditées manuellement (voir README.md) ou peuvent être branchées sur
un flux CTI payant (Recorded Future, Mandiant, GreyNoise, etc.) si vous en
avez un.

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import json
import sys
import urllib.request
from datetime import datetime, timedelta, timezone

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_FILE = "data.json"
MIN_ROWS = 12   # nombre minimum de vulnérabilités à afficher
MAX_ROWS = 20   # nombre maximum à afficher


def fetch_kev():
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "cyberwatch-bot/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def build_vulns(kev_json):
    """
    Prend les MAX_ROWS entrées les plus récentes du catalogue KEV (triées par
    date d'ajout décroissante), sans se limiter à une fenêtre de 7 jours.
    Cela garantit toujours entre MIN_ROWS et MAX_ROWS lignes affichées, même
    lors des semaines calmes où peu de nouvelles vulnérabilités sont ajoutées.
    """
    all_items = []
    for item in kev_json.get("vulnerabilities", []):
        try:
            added = datetime.strptime(item["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        all_items.append((added, item))

    all_items.sort(key=lambda x: x[0], reverse=True)
    selected = all_items[:MAX_ROWS]

    cutoff_recent = datetime.now(timezone.utc) - timedelta(days=7)
    rows = []
    for added, item in selected:
        rows.append({
            "cve": item.get("cveID", "N/A"),
            "product": f"{item.get('vendorProject','')} {item.get('product','')}".strip(),
            "type": item.get("vulnerabilityName", item.get("shortDescription", ""))[:90],
            # Le flux CISA KEV ne fournit pas de score CVSS : à enrichir via
            # l'API NVD (services.nvd.nist.gov) si besoin, avec une clé API
            # pour éviter le rate-limit de 5 req/30s en anonyme.
            "cvss": None,
            "exploit": True,  # présence dans KEV = exploitation active confirmée
            "poc": "unk",
            "deadline": item.get("dueDate", "—"),
            "past": added < cutoff_recent,
            "note": "Utilisée dans des campagnes ransomware" if item.get("knownRansomwareCampaignUse") == "Known" else None,
            "url": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID','')}",
        })
    return rows


def main():
    try:
        kev = fetch_kev()
    except Exception as e:
        print(f"[fetch_kev] Échec de récupération du flux CISA KEV : {e}", file=sys.stderr)
        sys.exit(1)

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    new_vulns = build_vulns(kev)
    if new_vulns:
        data["vulns"] = new_vulns
    # Si le flux CISA KEV est momentanément inaccessible ou vide, on conserve
    # volontairement les entrées précédentes plutôt que de vider la page.

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_kev] {len(new_vulns)} vulnérabilité(s) mise(s) à jour depuis CISA KEV.")


if __name__ == "__main__":
    main()
