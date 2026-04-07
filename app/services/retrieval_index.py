import joblib
from typing import List, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class TfidfAttackIndex:
    def __init__(self):
        self.vectorizer = None
        self.matrix = None
        self.techniques = []

    def build(self, techniques: List[dict]) -> None:
        self.techniques = techniques
        corpus = [t["corpus_text"] if isinstance(t, dict) else t.corpus_text for t in techniques]

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            lowercase=True,
            min_df=1,
            norm="l2",
        )

        self.matrix = self.vectorizer.fit_transform(corpus)

    def query(self, text: str, top_k: int = 15) -> List[Tuple[dict, float]]:
        if self.vectorizer is None or self.matrix is None:
            raise RuntimeError("TF-IDF index not built")

        q = self.vectorizer.transform([text])
        sims = cosine_similarity(q, self.matrix)[0]
        ranked_idx = sims.argsort()[::-1][:top_k]

        results = []
        for idx in ranked_idx:
            results.append((self.techniques[idx], float(sims[idx])))
        return results

    def save(self, vectorizer_path: str, matrix_path: str, techniques_path: str) -> None:
        joblib.dump(self.vectorizer, vectorizer_path)
        joblib.dump(self.matrix, matrix_path)
        joblib.dump(self.techniques, techniques_path)

    def load(self, vectorizer_path: str, matrix_path: str, techniques_path: str) -> None:
        self.vectorizer = joblib.load(vectorizer_path)
        self.matrix = joblib.load(matrix_path)
        self.techniques = joblib.load(techniques_path)
