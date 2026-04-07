import json
import numpy as np
from core.embedder import AttackEmbedder

INPUT_FILE = "data/processed/attack_techniques.json"


def main():
    with open(INPUT_FILE) as f:
        techniques = json.load(f)

    embedder = AttackEmbedder()
    embedder.build(techniques)

    np.save("data/processed/embeddings.npy", embedder.embeddings)

    print("[+] Embeddings built")
    print(f"[+] Techniques embedded: {len(techniques)}")


if __name__ == "__main__":
    main()
