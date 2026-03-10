import json
import requests #envoyer des requetes http a ollama

DATASET_FILE = "dataset/domain_dataset.jsonl"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "mistral"

print("=" * 60)
print("  CHATBOT T.I — Mistral via Ollama (Mode Local)")
print("=" * 60)

print("\n Chargement du dataset domaines...")
domain_db = {} #creer un dico vide pour stocker les domaines et leurs infos
with open(DATASET_FILE, "r", encoding="utf-8") as f:
    for line in f:
        entry = json.loads(line) #linverse de json.dumps donc convertir la l json en dic
        val = entry["value"].lower() # mtr en miniscule le domain
        domain_db[val] = entry["info"] #
        domain_db[val.replace("www.", "")] = entry["info"]

print(f"✅ {len(domain_db)} domaines chargés")

def normalize_domain(domain):
    domain = domain.lower().strip()
    domain = domain.replace("https://", "").replace("http://", "")
    domain = domain.replace("www.", "")
    domain = domain.split("/")[0]
    return domain

def check_domain(domain):
    domain = normalize_domain(domain)
    if domain in domain_db:
        return f"DOMAINE MALVEILLANT DÉTECTÉ : {domain}\nInfo : {domain_db[domain]}"
    if f"www.{domain}" in domain_db:
        return f"DOMAINE MALVEILLANT DÉTECTÉ : www.{domain}\nInfo : {domain_db[f'www.{domain}']}"

    return None

def ask_mistral(question, context=None):
    if context:
        prompt = f"""Tu es un expert en cybersécurité.
Base de données TI :
{context}
Question : {question}
Réponds dans la langue avec laquelle on t'a posé la question, de façon concise."""
    else:
        prompt = f"""Tu es un expert en cybersécurité.
Question : {question}
Réponds dans la langue avec laquelle on t'a posé la question, de façon concise."""
    try:
        r = requests.post(OLLAMA_URL, json={
            "model": MODEL,
            "prompt": prompt,
            "stream": False
        }, timeout=60)
        try:
            data = r.json()
            return data.get("response", "Erreur")
        except:
            # Si erreur JSON, essayer de nettoyer
            response_text = r.text.strip()
            if response_text:
                # Chercher le dernier JSON valide
                for line in response_text.split('\n')[::-1]:  # Inverse
                    try:
                        data = json.loads(line)
                        return data.get("response", "Erreur")
                    except:
                        continue
            return "Erreur: Pas de réponse valide"
        
    except Exception as e:
        return f"❌Erreur : {e}"

while True:
    user_input = input("\n👤 Toi : ").strip()
    if not user_input:
        continue
    if user_input.lower() in ["quit", "exit", "bye"]:
        print("👋 Au revoir !")
        break

    words = user_input.replace(",", " ").replace("?", " ").split()
    context = None
    for word in words:
        result = check_domain(word)
        if result:
            context = result
            break

    if context:
        print(f"\n🔍 Dataset : {context}")

    print("\n🤖 Mistral : ", end="", flush=True)
    print(ask_mistral(user_input, context))
    print("-" * 61)