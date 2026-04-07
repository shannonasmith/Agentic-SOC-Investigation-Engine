from core.attack_loader import load_attack_stix
from core.attack_preprocessor import preprocess_techniques, save_processed_techniques


RAW_ATTACK_FILE = "data/raw/enterprise-attack.json"
PROCESSED_TECHNIQUES = "data/processed/attack_techniques.json"


def main():
    techniques, _ = load_attack_stix(RAW_ATTACK_FILE)
    techniques = preprocess_techniques(techniques)
    save_processed_techniques(techniques, PROCESSED_TECHNIQUES)

    print(f"[+] Loaded techniques: {len(techniques)}")
    if techniques:
        print(f"[+] First technique: {techniques[0].technique_id} - {techniques[0].name}")
        print(f"[+] Output written to: {PROCESSED_TECHNIQUES}")


if __name__ == "__main__":
    main()
