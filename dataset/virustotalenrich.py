import json
import requests
import time
import os
VT_API_KEY = os.getenv("VT_API_KEY")

# ============================================================
# Script : Enrichissement dataset domaines via VirusTotal
# Output : domain_dataset.json
# Format : {"type": "domain", "value": "...", "info": "..."}
# ============================================================

GITHUB_URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt"
OUTPUT_FILE = "dataset/domain_dataset.json"
MAX_DOMAINS = 10      # Change à 500 quand le test est ok
DELAY = 16

# Types de menaces connus
KNOWN_THREATS = [
    "phishing", "malware", "ransomware", "trojan", "spyware",
    "botnet", "spam", "scam", "fraud", "exploit", "adware",
    "cryptominer", "backdoor", "c2", "command and control"
]

# ============================================================
# 1. Télécharger les domaines depuis GitHub
# ============================================================
def download_domains():
    print("📥 Téléchargement des domaines depuis GitHub...")
    response = requests.get(GITHUB_URL, timeout=30)
    lines = [l.strip() for l in response.text.splitlines() if l.strip() and not l.startswith("#")]
    print(f"✅ {len(lines)} domaines téléchargés")
    return lines[:MAX_DOMAINS]

# ============================================================
# 2. Extraire le type de menace
# ============================================================
def extract_threat_type(attributes):
    """Cherche le type de menace dans plusieurs champs VirusTotal"""

    # 1. Chercher dans les catégories
    categories = attributes.get("categories", {})
    for cat in categories.values():
        cat_lower = cat.lower()
        for threat in KNOWN_THREATS:
            if threat in cat_lower:
                return threat

    # 2. Chercher dans les résultats d'analyse
    results = attributes.get("last_analysis_results", {})
    for engine, result in results.items():
        if result.get("category") in ["malicious", "suspicious"]:
            res = (result.get("result") or "").lower()
            if res in ["malicious", "suspicious", ""]:
                continue
            for threat in KNOWN_THREATS:
                if threat in res:
                    return threat
            if res:
                return res

    # 3. Chercher dans les tags
    tags = attributes.get("tags", [])
    for tag in tags:
        tag_lower = tag.lower()
        for threat in KNOWN_THREATS:
            if threat in tag_lower:
                return threat

    return None

# ============================================================
# 3. Vérifier un domaine sur VirusTotal
# ============================================================
def check_virustotal(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 200:
            data = response.json()
            attributes = data["data"]["attributes"]
            stats = attributes["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            threat_type = extract_threat_type(attributes)

            if malicious > 0:
                info = f"malicious:{threat_type}" if threat_type else "malicious:unknown"
            elif suspicious > 0:
                info = f"suspicious:{threat_type}" if threat_type else "suspicious:unknown"
            else:
                info = "clean:no_threat_detected"

            return {"type": "domain", "value": domain, "info": info}

        elif response.status_code == 404:
            return {"type": "domain", "value": domain, "info": "unknown:not_found"}

        elif response.status_code == 429:
            print("⚠️ Limite API atteinte, on attend 60 secondes...")
            time.sleep(60)
            return check_virustotal(domain)

        else:
            print(f"❌ Erreur {response.status_code} pour {domain}")
            return None

    except Exception as e:
        print(f"❌ Erreur pour {domain}: {e}")
        return None

# ============================================================
# 4. Main
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("  VIRUSTOTAL DOMAIN ENRICHMENT — Chatbot T.I")
    print("=" * 60)

    if VT_API_KEY == "METS_TA_CLE_ICI":
        print("❌ Tu n'as pas mis ta clé API VirusTotal !")
        exit(1)

    domains = download_domains()
    results = []
    total = len(domains)

    print(f"\n🔍 Analyse de {total} domaines sur VirusTotal...")
    print(f"⏳ Durée estimée : ~{(total * DELAY) // 60} minutes\n")

    for i, domain in enumerate(domains):
        print(f"[{i+1}/{total}] Analyse de {domain}...", end=" ")

        result = check_virustotal(domain)

        if result:
            results.append(result)
            print(f"✅ {result['info']}")
        else:
            print("⏭️ Ignoré")

        # Sauvegarder toutes les 50 entrées
        if (i + 1) % 50 == 0:
            with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"\n💾 Sauvegarde intermédiaire : {len(results)} entrées\n")

        if i < total - 1:
            time.sleep(DELAY)

    # Sauvegarde finale
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    malicious = sum(1 for r in results if r["info"].startswith("malicious"))

    print(f"\n{'='*60}")
    print(f"🎉 Terminé !")
    print(f"📊 Total analysé   : {len(results)}")
    print(f"⚠️  Malveillants    : {malicious}")
    print(f"✅ Sains           : {len(results) - malicious}")
    print(f"📁 Fichier généré  : {OUTPUT_FILE}")
    print(f"{'='*60}")