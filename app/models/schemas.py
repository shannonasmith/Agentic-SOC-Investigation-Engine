from dataclasses import dataclass, field
from typing import List


@dataclass
class AttackTechnique:
    stix_id: str
    technique_id: str
    name: str
    description: str
    tactics: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    data_sources: List[str] = field(default_factory=list)
    detection: str = ""
    url: str = ""
    corpus_text: str = ""
