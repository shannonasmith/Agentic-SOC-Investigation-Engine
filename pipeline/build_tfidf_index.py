from core.retrieval_index import TfidfAttackIndex

INPUT_FILE = "data/processed/attack_techniques.json"


def main():
    index = TfidfAttackIndex()
    index.load_processed_data(INPUT_FILE)
    index.build()
    index.save()

    print("[+] TF-IDF index built successfully")
    print(f"[+] Techniques indexed: {len(index.techniques)}")


if __name__ == "__main__":
    main()
