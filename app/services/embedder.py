import os
import numpy as np
from typing import List, Tuple
from sentence_transformers import SentenceTransformer


class AttackEmbedder:
    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = SentenceTransformer(model_name)
        self.techniques = []
        self.embeddings = None

    def build(self, techniques: List) -> None:
        self.techniques = techniques
        corpus = [
            t.corpus_text if hasattr(t, "corpus_text") else t["corpus_text"]
            for t in techniques
        ]

        self.embeddings = self.model.encode(
            corpus,
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=True,
        )

    def query(self, text: str, candidates: List, top_k: int = 5) -> List[Tuple[object, float]]:
        if self.embeddings is None:
            raise RuntimeError("Embedding index not built")

        if not candidates:
            return []

        query_emb = self.model.encode(
            [text],
            convert_to_numpy=True,
            normalize_embeddings=True,
            show_progress_bar=False,
        )[0]

        def get_tid(x):
            return x.technique_id if hasattr(x, "technique_id") else x["technique_id"]

        candidate_idx = {get_tid(t): i for i, t in enumerate(self.techniques)}

        scored = []
        for t in candidates:
            tid = get_tid(t)
            idx = candidate_idx[tid]
            score = float(np.dot(query_emb, self.embeddings[idx]))
            scored.append((t, score))

        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    def save(self, embeddings_path: str) -> None:
        os.makedirs(os.path.dirname(embeddings_path), exist_ok=True)
        np.save(embeddings_path, self.embeddings)

    def load(self, techniques: List, embeddings_path: str) -> None:
        self.techniques = techniques
        self.embeddings = np.load(embeddings_path)
