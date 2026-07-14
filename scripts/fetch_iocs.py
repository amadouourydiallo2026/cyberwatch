#!/usr/bin/env python3
"""
Met à jour data.json avec les indicateurs de compromission (IOC) liés aux
vulnérabilités activement exploitées déjà listées dans data.json["vulns"]
(elles-mêmes alimentées par fetch_kev.py depuis le catalogue CISA KEV).

Principe : pour chaque CVE de la liste, on interroge ThreatFox (abuse.ch)
avec cette CVE comme "tag" — de nombreux contributeurs ThreatFox taguent
leurs soumissions avec l'identifiant CVE de la vulnérabilité exploitée.
Seuls les IOC réellement associés à une CVE de ta page apparaissent donc
dans l'onglet IOC, au lieu d'un flux générique sans rapport.

Limite connue et assumée : toutes les CVE ne sont pas nécessairement taguées
sur ThreatFox (dépend de ce que la communauté a soumis). Certaines CVE de ta
liste peuvent donc n'avoir aucun IOC associé — c'est normal et attendu,
préférable à afficher de faux résultats non liés.

ThreatFox est un projet public et gratuit de la fondation abuse.ch. Une clé
API (Auth-Key) est obligatoire depuis 2025, mais gratuite : à générer sur
https://auth.abuse.ch/ (connexion via Google/GitHub/LinkedIn/X), puis à
ajouter comme secret GitHub THREATFOX_AUTH_KEY.

Ces IOC sont destinés à un usage strictement défensif (règles de blocage,
détection SIEM) — jamais à être visités ou exécutés.

Lancé chaque jour par .github/workflows/daily-update.yml, juste après
fetch_kev.py (dont il dépend : il lit les CVE que ce dernier vient d'écrire
dans data.json).
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"
DATA_FILE = "data.json"
MAX_ROWS = 20
DELAY_BETWEEN_CALLS = 1.2  # secondes, pour rester raisonnable vis-à-vis de l'API publique


def query_threatfox(payload_dict, auth_key):
    payload = json.dumps(payload_dict).encode("utf-8")
    req = urllib.request.Request(
        THREATFOX_API,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "cyberwatch-bot/1.0",
            "Auth-Key": auth_key,
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_iocs_for_cve(cve_id, auth_key):
    """Interroge ThreatFox pour les IOC tagués avec cette CVE. Retourne [] si
    aucun résultat ou en cas d'erreur (une CVE sans IOC n'est pas une erreur
    fatale pour le job)."""
    try:
        result = query_threatfox({"query": "taginfo", "tag": cve_id, "limit": 10}, auth_key)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        print(f"[fetch_iocs] {cve_id} : erreur HTTP {e.code}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"[fetch_iocs] {cve_id} : erreur réseau ({e})", file=sys.stderr)
        return []

    if result.get("query_status") != "ok":
        return []

    items = result.get("data", [])
    if not isinstance(items, list):
        return []

    rows = []
    for item in items:
        ioc_id = item.get("id", "")
        rows.append({
            "type": item.get("ioc_type", "unknown"),
            "value": item.get("ioc", ""),
            "malware": item.get("malware_printable") or item.get("malware") or None,
            "confidence": item.get("confidence_level"),
            "first_seen": (item.get("first_seen") or "")[:10],
            "related_cve": cve_id,
            "source": "ThreatFox",
            "source_url": f"https://threatfox.abuse.ch/ioc/{ioc_id}/" if ioc_id else "https://threatfox.abuse.ch/",
        })
    return rows


def main():
    auth_key = os.environ.get("THREATFOX_AUTH_KEY")
    if not auth_key:
        print("[fetch_iocs] THREATFOX_AUTH_KEY absent — clé gratuite à générer sur https://auth.abuse.ch/", file=sys.stderr)
        sys.exit(1)

    with open(DATA_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)

    cve_list = [v["cve"] for v in data.get("vulns", []) if v.get("cve")]
    if not cve_list:
        print("[fetch_iocs] Aucune CVE dans data.json — lancez fetch_kev.py avant ce script.", file=sys.stderr)
        sys.exit(1)

    all_iocs = []
    cves_with_hits = 0
    for i, cve_id in enumerate(cve_list):
        rows = fetch_iocs_for_cve(cve_id, auth_key)
        if rows:
            cves_with_hits += 1
            all_iocs.extend(rows)
        if i < len(cve_list) - 1:
            time.sleep(DELAY_BETWEEN_CALLS)

    # Les plus fiables et les plus récents en premier
    all_iocs.sort(key=lambda x: (x.get("confidence") or 0, x.get("first_seen") or ""), reverse=True)
    all_iocs = all_iocs[:MAX_ROWS]

    # Si ThreatFox ne renvoie rien du tout pour aucune CVE (arrive certaines
    # semaines calmes), on conserve les IOC précédents plutôt que de vider
    # l'onglet — mêmes principe que fetch_kev.py pour les vulnérabilités.
    if all_iocs:
        data["iocs"] = all_iocs

    data["generated_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    with open(DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    print(f"[fetch_iocs] {len(all_iocs)} IOC trouvés, liés à {cves_with_hits}/{len(cve_list)} CVE interrogées sur ThreatFox.")


if __name__ == "__main__":
    main()
