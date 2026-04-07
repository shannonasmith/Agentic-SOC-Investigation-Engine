import json
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class TfidfAttackIndex:
    def __init__(self):
        self.vectorizer = None
        self.matrix = None
        self.techniques = []

    def load_processed_data(self, file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            self.techniques = json.load(f)

    def build(self):
        corpus = [t["corpus_text"] for t in self.techniques]

        self.vectorizer = TfidfVectorizer(
            ngram_range=(1, 2),
            stop_words="english",
            lowercase=True
        )

        self.matrix = self.vectorizer.fit_transform(corpus)

    def query(self, text, top_k=5):
        query_vec = self.vectorizer.transform([text])
        scores = cosine_similarity(query_vec, self.matrix)[0]

        ranked_idx = scores.argsort()[::-1][:top_k]

        results = []
        for idx in ranked_idx:
            results.append({
                "technique_id": self.techniques[idx]["technique_id"],
                "name": self.techniques[idx]["name"],
                "score": float(scores[idx]),
                "tactics": self.techniques[idx]["tactics"]
            })

        return results

    def save(self):
        joblib.dump(self.vectorizer, "data/processed/tfidf_vectorizer.pkl")
        joblib.dump(self.matrix, "data/processed/tfidf_matrix.pkl")

    def load(self):
        self.vectorizer = joblib.load("data/processed/tfidf_vectorizer.pkl")
        self.matrix = joblib.load("data/processed/tfidf_matrix.pkl")
