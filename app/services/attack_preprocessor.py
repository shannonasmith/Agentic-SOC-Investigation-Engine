import re
from typing import List

from app.utils.io_helpers import save_json


def normalize_text(text: str) -> str:
    text = text or ""
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"[\r\n\t]+", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def build_corpus_text(technique) -> str:
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


def preprocess_techniques(techniques: List) -> List:
    for t in techniques:
        t.corpus_text = build_corpus_text(t)
    return techniques


def save_processed_techniques(techniques: List, file_path: str) -> None:
    data = []
    for t in techniques:
        data.append(
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

    save_json(data, file_path)
