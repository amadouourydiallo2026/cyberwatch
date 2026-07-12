#!/usr/bin/env python3
"""
Envoie un résumé hebdomadaire à partir de data.json.

Par défaut : Slack, via une Incoming Webhook (le plus simple à mettre en
place, aucun mot de passe email à gérer).
  1. Slack > Paramètres > Apps > "Incoming Webhooks" > créer un webhook
  2. Ajouter l'URL obtenue comme secret GitHub : SLACK_WEBHOOK_URL

Variante email : voir la fonction send_email() plus bas, désactivée par
défaut. Fonctionne avec n'importe quel SMTP (Gmail avec un "mot de passe
d'application", Outlook, ou un service comme Resend/SendGrid).

Lancé chaque lundi par .github/workflows/monday-digest.yml
"""
import json
import os
import smtplib
import sys
import urllib.request
from email.mime.text import MIMEText

DATA_FILE = "data.json"


def load_data():
    with open(DATA_FILE, "r", encoding="utf-8") as f:
        return json.load(f)


def build_summary_text(data):
    n_attacks = len(data.get("attacks", []))
    n_vulns = len(data.get("vulns", []))
    n_critical = sum(1 for v in data.get("vulns", []) if (v.get("cvss") or 0) >= 9)
    n_actors = len(data.get("actors", []))
    top_threats = data.get("threats", [])[:3]

    lines = [
        f"*🛰️ CyberWatch — résumé hebdomadaire* ({data.get('week_label','')})",
        "",
        f"• {n_attacks} cyberattaques suivies",
        f"• {n_vulns} vulnérabilités critiques (dont {n_critical} avec CVSS ≥ 9)",
        f"• {n_actors} threat actors actifs",
        "",
        "*Top menaces de la semaine :*",
    ]
    for i, t in enumerate(top_threats, 1):
        lines.append(f"{i}. {t['title']} — {t['url']}")
    lines.append("")
    lines.append("Détails complets sur le dashboard.")
    return "\n".join(lines)


def send_slack(text):
    webhook = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook:
        print("[send_digest] SLACK_WEBHOOK_URL absent, envoi Slack ignoré.", file=sys.stderr)
        return False
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(webhook, data=payload, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        return resp.status == 200


def send_email(text):
    """Variante email — désactivée par défaut, appelez-la depuis main() si besoin."""
    smtp_host = os.environ["SMTP_HOST"]
    smtp_user = os.environ["SMTP_USER"]
    smtp_pass = os.environ["SMTP_PASS"]
    to_addr = os.environ["DIGEST_RECIPIENT"]

    msg = MIMEText(text, "plain", "utf-8")
    msg["Subject"] = "CyberWatch — résumé hebdomadaire"
    msg["From"] = smtp_user
    msg["To"] = to_addr

    with smtplib.SMTP_SSL(smtp_host, 465) as server:
        server.login(smtp_user, smtp_pass)
        server.sendmail(smtp_user, [to_addr], msg.as_string())


def main():
    data = load_data()
    text = build_summary_text(data)

    sent = send_slack(text)
    # Pour activer l'email à la place ou en plus, décommentez :
    # send_email(text)

    if not sent:
        print(text)  # au minimum, affiche le résumé dans les logs GitHub Actions
        sys.exit(0)

    print("[send_digest] Résumé envoyé sur Slack.")


if __name__ == "__main__":
    main()
