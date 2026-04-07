from core.retrieval_index import TfidfAttackIndex
from core.embedder import AttackEmbedder
import numpy as np


class AttackMapper:
    def __init__(self):
        self.index = TfidfAttackIndex()
        self.index.load_processed_data("data/processed/attack_techniques.json")
        self.index.load()

        self.embedder = AttackEmbedder()
        self.embedder.techniques = self.index.techniques
        self.embedder.embeddings = np.load("data/processed/embeddings.npy")

    def build_query(self, alert):
    parts = []

    # Raw fields
    for key in [
        "event_type",
        "details",
        "process_name",
        "command_line",
        "username",
        "target_user",
    ]:
        if alert.get(key):
            parts.append(str(alert[key]))

    query = " ".join(parts).lower()

    # 🔥 Add semantic enrichment
    if "failed login" in query or "authentication_failure" in query:
        query += " brute force password guessing credential access"

    if "powershell" in query:
        query += " execution powershell command scripting"

    if "psexec" in query:
        query += " lateral movement remote execution"

    if "wmic" in query:
        query += " lateral movement remote execution discovery"

    if "encodedcommand" in query or "encoded command" in query:
        query += " obfuscation defense evasion"

    return query
    
    def build_reasoning(self, alert, match):
        reasoning = []
        query = self.build_query(alert)

        if "failed login" in query and "brute force" in match["name"].lower():
            reasoning.append(
                "Alert contains repeated authentication-failure language consistent with brute-force behavior"
            )

        if "powershell" in query and "powershell" in match["name"].lower():
            reasoning.append(
                "Alert references PowerShell execution and matched a PowerShell-related technique"
            )

        if "encodedcommand" in query or "encoded command" in query:
            reasoning.append(
                "Encoded command activity increases likelihood of execution-oriented ATT&CK techniques"
            )

        if "psexec" in query:
            reasoning.append(
                "PsExec activity suggests remote service execution or lateral movement behavior"
            )

        if "wmic" in query:
            reasoning.append(
                "WMIC activity may indicate remote execution, discovery, or lateral movement behavior"
            )

        if not reasoning:
            reasoning.append(
                "Technique was selected using hybrid TF-IDF candidate retrieval and semantic embedding reranking"
            )

        return reasoning

    def map_alert(self, alert, top_k=5):
        query = self.build_query(alert)

        # Step 1: broader TF-IDF candidate set
        tfidf_results = self.index.query(query, top_k=15)

        # Step 2: semantic rerank
        embedding_results = self.embedder.query(query, tfidf_results)

        final = []

        for item, emb_score in embedding_results:
            tfidf_score = item["score"]

            final_score = (0.4 * tfidf_score) + (0.6 * emb_score)

            enriched_item = dict(item)
            enriched_item["tfidf_score"] = round(tfidf_score, 4)
            enriched_item["embedding_score"] = round(emb_score, 4)
            enriched_item["final_score"] = round(final_score, 4)

            final.append(enriched_item)

        # IMPORTANT: sort by final score before truncating and before confidence normalization
        final.sort(key=lambda x: x["final_score"], reverse=True)
        final = final[:top_k]

        max_score = final[0]["final_score"] if final else 1.0

        for r in final:
            r["confidence"] = round((r["final_score"] / max_score) * 100, 2) if max_score > 0 else 0.0
            r["reasoning"] = self.build_reasoning(alert, r)

        return {
            "alert": alert,
            "query_used": query,
            "matches": final
        }
