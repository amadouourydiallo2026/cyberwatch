# CyberWatch — Plateforme de veille CTI

Dashboard statique (`index.html` + `data.json`) avec mise à jour automatique
quotidienne et résumé Slack chaque lundi, via GitHub Actions.

## ⚠️ Pourquoi GitHub Actions et pas "juste le fichier HTML" ?

Un fichier HTML ouvert dans un navigateur ne s'exécute que lorsque la page
est ouverte : il ne peut pas se réveiller seul chaque jour, ni envoyer un
message tout seul. Il faut un processus qui tourne quelque part, à heure
fixe, même quand personne n'a la page ouverte. GitHub Actions fait ça
gratuitement (2 000 min/mois sur un compte gratuit, largement suffisant
pour ce projet) — pas besoin de serveur à gérer.

## Mise en route (10 minutes)

1. **Créer un dépôt GitHub** et y pousser ce dossier tel quel :
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git branch -M main
   git remote add origin https://github.com/<votre-compte>/cyberwatch.git
   git push -u origin main
   ```

2. **Activer GitHub Pages** : Settings → Pages → Source = "Deploy from a
   branch" → branche `main`, dossier `/ (root)`. Votre dashboard sera en
   ligne sur `https://<votre-compte>.github.io/cyberwatch/`.

   *(Nécessaire aussi pour que `fetch('./data.json')` fonctionne : ouvert en
   double-clic depuis votre disque, la plupart des navigateurs bloquent
   cette requête pour des raisons de sécurité.)*

3. **Créer le webhook Slack** (pour le message du lundi) :
   Slack → Paramètres de l'espace de travail → Apps → *Incoming Webhooks* →
   créer un webhook sur le canal souhaité → copier l'URL.

4. **Ajouter le secret dans GitHub** : Settings → Secrets and variables →
   Actions → *New repository secret* → nom `SLACK_WEBHOOK_URL`, valeur =
   l'URL copiée à l'étape 3.

5. C'est tout. Les deux workflows dans `.github/workflows/` se déclenchent
   automatiquement :
   - `daily-update.yml` — tous les jours à 06:00 UTC, met à jour `data.json`
     depuis le catalogue officiel **CISA KEV**.
   - `monday-digest.yml` — chaque lundi à 07:00 UTC, envoie le résumé sur
     Slack.

   Vous pouvez aussi les lancer manuellement depuis l'onglet **Actions** du
   dépôt (bouton "Run workflow") pour tester sans attendre.

## Ce qui est réellement automatisé, et ce qui ne l'est pas

| Section | Automatisation |
|---|---|
| **Vulnérabilités** | ✅ Entièrement automatique via le flux public CISA KEV (`scripts/fetch_kev.py`) |
| **Cyberattaques** | ✋ Édition manuelle de `data.json` — aucun flux public unique et fiable ne liste "les attaques les plus commentées" ; nécessiterait un abonnement CTI payant (Recorded Future, Mandiant, GreyNoise…) pour être automatisé |
| **Threat actors** | ✋ Édition manuelle, même raison |
| **Menaces de la semaine** | ✋ Édition manuelle / curation d'analyste |

Pour éditer les sections manuelles, modifiez simplement les tableaux
correspondants dans `data.json` et poussez le commit — la page se mettra à
jour au prochain chargement.

## Ajouter le score CVSS automatiquement (optionnel)

Le flux CISA KEV ne contient pas le score CVSS. Pour l'enrichir
automatiquement, appelez l'API NVD (`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX`)
pour chaque CVE dans `fetch_kev.py`. Sans clé API, la limite est de 5
requêtes / 30 secondes ; demandez une clé gratuite sur
https://nvd.nist.gov/developers/request-an-api-key pour passer à 50/30s.

## Fichiers

```
index.html                        → le dashboard
data.json                         → les données affichées (source de vérité)
scripts/fetch_kev.py              → mise à jour quotidienne des vulnérabilités
scripts/send_digest.py            → résumé Slack du lundi
.github/workflows/daily-update.yml
.github/workflows/monday-digest.yml
```
