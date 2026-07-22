"""
Détecte les articles quasi-identiques publiés par plusieurs sources
différentes sur le MÊME événement (ex. BleepingComputer et The Hacker News
couvrant tous les deux l'attaque Coca-Cola/Fairlife), pour ne garder qu'une
seule occurrence — sans quoi le même événement serait compté/affiché
plusieurs fois.

Méthode (sans IA, gratuite) : similarité de Jaccard sur les mots
significatifs du titre (≥4 lettres, hors mots vides). Deux titres qui
partagent une bonne part de leurs mots-clés (noms d'entreprise, de groupe...)
sont considérés comme le même événement, même si la formulation diffère
selon la source.

Utilisé par fetch_attacks.py et fetch_actors.py.
"""
import html
import re

STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "on", "for", "is", "are",
    "says", "say", "said", "after", "new", "its", "with", "from", "that",
    "this", "by", "at", "as", "has", "have", "had", "not", "over", "into",
    "now", "how", "what", "who", "were", "was", "will", "been",
    "le", "la", "les", "des", "du", "de", "un", "une", "et", "pour", "dans",
    "sur", "apres", "après", "son", "sa", "ses", "avec", "par", "plus",
    # Termes génériques cyber trop fréquents pour être discriminants (sans
    # ça, deux incidents SANS RAPPORT partageant juste "ransomware"/"attack"
    # se rapprocheraient artificiellement du seuil de duplication).
    "ransomware", "attack", "attacks", "attaque", "breach", "hacked", "hack",
    "data", "victim", "victims", "victime", "company", "group", "groupe",
    "cyberattack", "cyberattaque", "malware", "security", "sécurité",
}


def normalize_words(title):
    title = html.unescape(title or "")
    words = re.findall(r"[a-zà-ÿ0-9]+", title.lower())
    return {w for w in words if len(w) >= 4 and w not in STOPWORDS}


def jaccard(set_a, set_b):
    if not set_a or not set_b:
        return 0.0
    inter = len(set_a & set_b)
    union = len(set_a | set_b)
    return inter / union if union else 0.0


def dedupe_articles(items, threshold=0.35, source_priority=None):
    """items : liste de dicts avec au moins les clés 'title' et 'source'.
    Retourne une liste où chaque groupe d'articles quasi-identiques
    (probablement le même événement couvert par plusieurs médias) n'est
    représenté qu'une seule fois — en gardant en priorité la source listée
    en premier dans source_priority, sinon la première rencontrée."""
    source_priority = source_priority or []

    def prio(src):
        return source_priority.index(src) if src in source_priority else len(source_priority)

    word_sets = [normalize_words(it.get("title", "")) for it in items]
    assigned = [False] * len(items)
    result = []

    for i in range(len(items)):
        if assigned[i]:
            continue
        cluster = [i]
        assigned[i] = True
        for j in range(i + 1, len(items)):
            if assigned[j]:
                continue
            if jaccard(word_sets[i], word_sets[j]) >= threshold:
                cluster.append(j)
                assigned[j] = True

        best_idx = min(cluster, key=lambda idx: prio(items[idx].get("source", "")))
        result.append(items[best_idx])

    return result
