from sentence_transformers import SentenceTransformer
import numpy as np


class AttackEmbedder:
    def __init__(self):
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.techniques = []
        self.embeddings = None

    def build(self, techniques):
        self.techniques = techniques
        corpus = [t["corpus_text"] for t in techniques]

        self.embeddings = self.model.encode(
            corpus,
            convert_to_numpy=True,
            normalize_embeddings=True
        )

    def query(self, text, candidates):
        query_emb = self.model.encode(
            [text],
            convert_to_numpy=True,
            normalize_embeddings=True
        )[0]

        scores = []

        for c in candidates:
            idx = next(i for i, t in enumerate(self.techniques)
                       if t["technique_id"] == c["technique_id"])

            score = float(np.dot(query_emb, self.embeddings[idx]))
            scores.append((c, score))

        scores.sort(key=lambda x: x[1], reverse=True)

        return scores
