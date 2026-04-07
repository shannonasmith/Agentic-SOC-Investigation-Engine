from typing import Dict


class AttackMapper:
    def __init__(self, tfidf_index, embedder):
        self.tfidf_index = tfidf_index
        self.embedder = embedder

    def _safe_lower(self, value):
        return str(value or "").lower()

    def _build_alert_text(self, alert: Dict) -> str:
        parts = []

        for key in [
            "event_type",
            "log_source",
            "details",
            "command_line",
            "process_name",
            "username",
            "target_user",
            "source_ip",
            "destination_ip",
        ]:
            if alert.get(key):
                parts.append(str(alert.get(key)))

        text = " ".join(parts).lower()

        if "failed login" in text or "authentication_failure" in text:
            text += " brute force password guessing credential access"

        if "powershell" in text:
            text += " execution powershell command scripting"

        if "psexec" in text:
            text += " lateral movement remote execution"

        if "wmic" in text:
            text += " lateral movement remote execution discovery"

        if "encodedcommand" in text or "encoded command" in text:
            text += " obfuscation defense evasion"

        return text

    def _extract_http_features(self, alert: Dict):
        http = alert.get("http", {}) or {}

        method = self._safe_lower(http.get("method"))
        uri = self._safe_lower(http.get("uri"))
        ua = self._safe_lower(http.get("user_agent"))

        return {
            "method": method,
            "uri": uri,
            "ua": ua,
            "login_like": "login" in uri,
            "upload_like": method == "post" and "upload" in uri,
            "payload_like": method == "get" and (".zip" in uri or "payload" in uri),
            "scripted_http": any(x in ua for x in ["curl", "python", "wget"]),
        }

    def _rule_score(self, alert: Dict, technique_name: str, corpus_text: str):
        technique_text = f"{technique_name.lower()} {corpus_text.lower()}"
        alert_text = self._build_alert_text(alert)

        score = 0.0
        reasons = []

        service = self._safe_lower(alert.get("service"))
        dst_port = str(alert.get("dst_port", ""))
        http = self._extract_http_features(alert)

        if service == "smb" or dst_port == "445":
            if "smb" in technique_text:
                score += 1.0
                reasons.append("SMB activity")

        if service == "rdp" or dst_port == "3389":
            if "rdp" in technique_text:
                score += 1.0
                reasons.append("RDP activity")

        if "psexec" in alert_text:
            if "service execution" in technique_text or "remote service" in technique_text:
                score += 2.0
                reasons.append("PsExec remote service execution")

        if "wmic" in alert_text:
            if "windows management instrumentation" in technique_text or "remote execution" in technique_text:
                score += 1.5
                reasons.append("WMIC remote execution behavior")

        if "powershell" in alert_text:
            if "powershell" in technique_text or "command and scripting interpreter" in technique_text:
                score += 1.5
                reasons.append("PowerShell execution")

        if "failed login" in alert_text or "authentication_failure" in alert_text:
            if "brute force" in technique_text or "password guessing" in technique_text:
                score += 2.0
                reasons.append("Repeated failed authentication behavior")

        if http["upload_like"]:
            if "web shell" in technique_text:
                score += 2.0
                reasons.append("Web shell upload")

        if http["payload_like"]:
            if "ingress tool transfer" in technique_text:
                score += 2.0
                reasons.append("Payload download")

        return score, reasons

    def _normalize(self, scores):
        max_score = max(scores.values()) if scores else 1.0
        if max_score == 0:
            return {k: 0.0 for k in scores}
        return {k: v / max_score for k, v in scores.items()}

    def map_alert(self, alert: Dict, top_k_tfidf=15, top_k_final=5):
        query = self._build_alert_text(alert)

        tfidf_results = self.tfidf_index.query(query, top_k=top_k_tfidf)
        candidate_techniques = [t for t, _ in tfidf_results]

        http = self._extract_http_features(alert)

        if http["payload_like"]:
            extra = self.tfidf_index.query("ingress tool transfer", top_k=5)
            for t, _ in extra:
                if t not in candidate_techniques:
                    candidate_techniques.append(t)

        if http["upload_like"]:
            extra = self.tfidf_index.query("web shell exploit upload", top_k=5)
            for t, _ in extra:
                if t not in candidate_techniques:
                    candidate_techniques.append(t)

        embed_results = self.embedder.query(query, candidate_techniques, top_k=len(candidate_techniques))

        tfidf_scores = self._normalize({t.technique_id: s for t, s in tfidf_results})
        embed_scores = self._normalize({t.technique_id: s for t, s in embed_results})

        results = []

        for t in candidate_techniques:
            tid = t.technique_id

            tfidf_score = tfidf_scores.get(tid, 0.0)
            embedding_score = embed_scores.get(tid, 0.0)
            rule_score, reasons = self._rule_score(alert, t.name, t.corpus_text)
            field_match_score = 0.0

            final = (
                0.3 * tfidf_score +
                0.2 * embedding_score +
                0.5 * rule_score
            )

            results.append({
                "technique_id": tid,
                "name": t.name,
                "tactics": getattr(t, "tactics", []),
                "tfidf_score": round(tfidf_score, 4),
                "embedding_score": round(embedding_score, 4),
                "rule_score": round(rule_score, 4),
                "field_match_score": round(field_match_score, 4),
                "final_score": round(final, 4),
                "confidence": 0.0,
                "explanation": reasons,
            })

        results.sort(key=lambda x: x["final_score"], reverse=True)

        top = results[:top_k_final]
        max_score = top[0]["final_score"] if top else 1.0

        for r in top:
            r["confidence"] = round((r["final_score"] / max_score) * 100, 2) if max_score > 0 else 0.0

        return {
            "query_used": query,
            "matches": top,
        }
