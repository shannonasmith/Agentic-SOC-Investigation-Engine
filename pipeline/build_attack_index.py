import os

from app.services.attack_loader import load_attack_stix
from app.services.attack_preprocessor import preprocess_techniques, save_processed_techniques
from app.services.retrieval_index import TfidfAttackIndex
from app.services.embedder import AttackEmbedder
from app.config import (
    RAW_ATTACK_FILE,
    PROCESSED_TECHNIQUES_FILE,
    TFIDF_VECTORIZER_FILE,
    TFIDF_MATRIX_FILE,
    TFIDF_TECHNIQUES_FILE,
    EMBEDDINGS_FILE,
)


def main():
    os.makedirs("data/processed", exist_ok=True)

    techniques, _ = load_attack_stix(RAW_ATTACK_FILE)
    techniques = preprocess_techniques(techniques)
    save_processed_techniques(techniques, PROCESSED_TECHNIQUES_FILE)

    tfidf_index = TfidfAttackIndex()
    tfidf_index.build(techniques)
    tfidf_index.save(
        TFIDF_VECTORIZER_FILE,
        TFIDF_MATRIX_FILE,
        TFIDF_TECHNIQUES_FILE,
    )

    embedder = AttackEmbedder(model_name="all-MiniLM-L6-v2")
    embedder.build(techniques)
    embedder.save(EMBEDDINGS_FILE)

    print(f"[+] Built ATT&CK index with {len(techniques)} techniques")
    print(f"[+] Processed techniques: {PROCESSED_TECHNIQUES_FILE}")
    print(f"[+] TF-IDF vectorizer: {TFIDF_VECTORIZER_FILE}")
    print(f"[+] TF-IDF matrix: {TFIDF_MATRIX_FILE}")
    print(f"[+] TF-IDF techniques: {TFIDF_TECHNIQUES_FILE}")
    print(f"[+] Embeddings: {EMBEDDINGS_FILE}")


if __name__ == "__main__":
    main()
