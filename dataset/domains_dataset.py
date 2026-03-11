import requests # Télécharger des fichiers depuis Internet
import json #Travailler avec le format JSON
import re #Vérifier si du texte suit un certain motif


URL = "https://raw.githubusercontent.com/romainmarcoux/malicious-domains/main/full-domains-aa.txt"
OUTPUT_FILE = "domain_dataset.jsonl"
MAX_ENTRIES = 10000

def is_valid_domain(domain): #définit une fonction qui prend un domaine en entrée
    domain = domain.strip() #Nettoie le domaine en enlevant les espaces au début/fin
    if not domain or domain.startswith("#"):
        return False #vide ou commentaire
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$' #regex pour vérifier si le domaine est valide
    return re.match(pattern, domain) is not None # fonction de la bibliothèque re qui :Vérifie si un texte respecte un motif (pattern)
def download_domains():
    print("Téléchargement du dataset depuis GitHub en cours")
    try: #si faux continue jusqu'au crash
        response = requests.get(URL, timeout=30) #télécharge le fichier depuis l'URL si apres 30S ya r jechoue
        response.raise_for_status() #si il echoue alors erreur
        lines = response.text.splitlines() #il split le texte de git en lignes individuelles
        print(f"✅ {len(lines)} lignes téléchargées")#affiche le nombre de lignes téléchargées
        return lines #retourne la liste des dmns
    except Exception as erreur:
        print(f"Erreur de téléchargement : {erreur}")#affiche l'erreur si le téléchargement échoue00
        return [] #retourne une liste vide en cas d'erreur

def convert_to_jsonl(lines):
    print("Conversion en format JSONL est en cours...")
    entries = [] #liste pour stocker les entrées valides
    count = 0 #compteur pour limiter le nombre d'entrées traitées

    for line in lines:
        if count >= MAX_ENTRIES:
            break 

        domain = line.strip()
        if not is_valid_domain(domain): #si domain nn valide je passe au suivant
            continue
        entry = {
            "prompt": f"Is the domain '{domain}' malicious?",
            "response": f"Yes, the domain '{domain}' is classified as malicious. It has been flagged for hosting malware or being involved in malicious activity.",
            "type": "domain",
            "value": domain,
            "info": "Hosts malware or malicious activity"
        }
        entries.append(entry) #append est comme une pile elle prends entry et l'ajoute à la fin de la liste entries
        count += 1

    print(f"{len(entries)} entrées valides sont converties")
    return entries

def save_jsonl(entries):
    print(f"Sauvegarde dans '{OUTPUT_FILE}'...")
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f: #ouvrir le fichier en mode écriture et mtr dans f
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n") #json.dumps convertit l'entrée en une chaîne JSON, ensure_ascii=False permet de conserver les caractères spéciaux
    print(f"Le fichier '{OUTPUT_FILE}'est créé avec {len(entries)} entrées")

def show_sample(entries, n=3):
    print(f"\n Exemples ({n} premières entrées) :")
    print("-" * 60)
    for entry in entries[:n]:
        print(json.dumps(entry, indent=2, ensure_ascii=False)) #affiche les n premières entrées de manière lisible
        print("-" * 60)

if __name__ == "__main__":#si ce fichier est exécuté directement, alors le code suivant sera exécuté
    print("=" * 60) 
    print("  DOMAIN DATASET BUILDER — Chatbot T.I")
    print("=" * 60)

    lines = download_domains()

    if not lines:
        print("Aucune donnée récupérée")
        exit(1)

    entries = convert_to_jsonl(lines)

    if not entries:
        print("Aucune entrée valide trouvée.")
        exit(1)

    save_jsonl(entries)
    show_sample(entries)

    print("\n🎉 Dataset prêt pour le fine-tuning LoRA !")
    print(f"📁 Fichier généré : {OUTPUT_FILE}")
    print(f"📊 Nombre d'entrées : {len(entries)}") 