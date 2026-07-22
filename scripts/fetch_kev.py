#!/usr/bin/env python3
"""
Met à jour data.json avec les 12 à 20 vulnérabilités les plus récentes du
catalogue CISA KEV (Known Exploited Vulnerabilities), classées par date
d'ajout décroissante.

Ne touche qu'à la section "vulns" — les sections "attacks", "actors" et
"threats" sont automatisées séparément par fetch_attacks.py, fetch_actors.py
et fetch_threats.py (flux RSS de médias/labos de sécurité, sans clé API
payante). Voir ces scripts pour le détail de chaque source.

CISA KEV ne fournit ni score CVSS ni date de publication du CVE : ces deux
champs sont récupérés séparément via l'API NVD (National Vulnerability
Database), un appel par CVE.

Variable d'environnement optionnelle NVD_API_KEY : sans elle, l'API NVD
limite à 5 requêtes/30s (donc ~2 min pour 20 CVE) ; avec une clé gratuite
(https://nvd.nist.gov/developers/request-an-api-key), la limite passe à
50 requêtes/30s (~15s pour 20 CVE). Le script fonctionne dans les deux cas.

Lancé chaque jour par .github/workflows/daily-update.yml
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DATA_FILE = "data.json"
MIN_ROWS = 12   # nombre minimum de vulnérabilités à afficher
MAX_ROWS = 20   # nombre maximum à afficher

NVD_API_KEY = os.environ.get("NVD_API_KEY", "").strip()
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5  # secondes entre deux appels NVD


def fetch_kev():
    req = urllib.request.Request(KEV_URL, headers={"User-Agent": "cyberwatch-bot/1.0"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_nvd_details(cve_id, retries=2):
    """Retourne (cvss_score, published_date_str) pour un CVE donné, ou
    (None, None) si indisponible. N'interrompt jamais le script principal :
    une erreur ici ne doit pas faire échouer toute la mise à jour."""
    url = f"{NVD_URL}?cveId={cve_id}"
    headers = {"User-Agent": "cyberwatch-bot/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=20) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            break
        except urllib.error.HTTPError as e:
            if e.code in (403, 429) and attempt < retries:
                time.sleep(NVD_DELAY * 3)  # backoff en cas de rate-limit
                continue
            print(f"[fetch_kev] NVD indisponible pour {cve_id} ({e.code})", file=sys.stderr)
            return None, None
        except Exception as e:
            print(f"[fetch_kev] Erreur NVD pour {cve_id} : {e}", file=sys.stderr)
            return None, None
    else:
        return None, None

    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return None, None
    cve_data = vulns[0].get("cve", {})

    published = cve_data.get("published")  # ex. "2026-06-30T14:12:00.000"
    published_str = published[:10] if published else None

    metrics = cve_data.get("metrics", {})
    cvss_score = None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            cvss_score = entries[0].get("cvssData", {}).get("baseScore")
            if cvss_score is not None:
                break

    return cvss_score, published_str


def build_vulns(kev_json):
    """
    Prend les MAX_ROWS entrées les plus récentes du catalogue KEV (triées par
    date d'ajout décroissante), sans se limiter à une fenêtre de 7 jours.
    Cela garantit toujours entre MIN_ROWS et MAX_ROWS lignes affichées, même
    lors des semaines calmes où peu de nouvelles vulnérabilités sont ajoutées.
    Enrichit ensuite chaque entrée avec le score CVSS et la date de
    publication via l'API NVD.
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
    for i, (added, item) in enumerate(selected):
        cve_id = item.get("cveID", "N/A")

        cvss_score, published = (None, None)
        if cve_id != "N/A":
            if i > 0:
                time.sleep(NVD_DELAY)
            cvss_score, published = fetch_nvd_details(cve_id)

        rows.append({
            "cve": cve_id,
            "product": f"{item.get('vendorProject','')} {item.get('product','')}".strip(),
            "type": item.get("vulnerabilityName", item.get("shortDescription", ""))[:90],
            "cvss": cvss_score,
            "published": published,  # date de publication du CVE (NVD), ex. "2026-06-30"
            "exploit": True,  # présence dans KEV = exploitation active confirmée
            "poc": "unk",
            "deadline": item.get("dueDate", "—"),
            "past": added < cutoff_recent,
            "note": "Utilisée dans des campagnes ransomware" if item.get("knownRansomwareCampaignUse") == "Known" else None,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
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
