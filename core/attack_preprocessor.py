import json
import os
import re
from typing import List
from core.schemas import AttackTechnique


def normalize_text(text: str) -> str:
    text = text or ""
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_corpus_text(technique: AttackTechnique) -> str:
    parts = [
        f"technique id {technique.technique_id}",
        f"technique name {technique.name}",
        f"tactics {' '.join(technique.tactics)}",
        f"platforms {' '.join(technique.platforms)}",
        f"data sources {' '.join(technique.data_sources)}",
        f"description {technique.description}",
        f"detection {technique.detection}",
    ]
    return normalize_text(" ".join(parts))


def preprocess_techniques(techniques: List[AttackTechnique]) -> List[AttackTechnique]:
    for t in techniques:
        t.corpus_text = build_corpus_text(t)
    return techniques


def save_processed_techniques(techniques: List[AttackTechnique], file_path: str) -> None:
    os.makedirs(os.path.dirname(file_path), exist_ok=True)

    output = []
    for t in techniques:
        output.append(
            {
                "stix_id": t.stix_id,
                "technique_id": t.technique_id,
                "name": t.name,
                "description": t.description,
                "tactics": t.tactics,
                "platforms": t.platforms,
                "data_sources": t.data_sources,
                "detection": t.detection,
                "url": t.url,
                "corpus_text": t.corpus_text,
            }
        )

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2)
