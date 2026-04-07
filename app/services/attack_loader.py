from typing import Dict, List, Tuple

from app.models.schemas import AttackTechnique
from app.utils.io_helpers import load_json


def _extract_external_id(external_references: List[dict]) -> str:
    for ref in external_references or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _extract_url(external_references: List[dict]) -> str:
    for ref in external_references or []:
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def load_attack_stix(file_path: str) -> Tuple[List[AttackTechnique], Dict[str, dict]]:
    bundle = load_json(file_path)
    objects = bundle.get("objects", [])
    by_id = {obj["id"]: obj for obj in objects if "id" in obj}

    techniques: List[AttackTechnique] = []

    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue

        if obj.get("revoked") is True or obj.get("x_mitre_deprecated") is True:
            continue

        technique_id = _extract_external_id(obj.get("external_references", []))
        if not technique_id.startswith("T"):
            continue

        tactics = [
            phase.get("phase_name", "")
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == "mitre-attack"
        ]

        techniques.append(
            AttackTechnique(
                stix_id=obj["id"],
                technique_id=technique_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                tactics=tactics,
                platforms=obj.get("x_mitre_platforms", []),
                data_sources=obj.get("x_mitre_data_sources", []),
                detection=obj.get("x_mitre_detection", ""),
                url=_extract_url(obj.get("external_references", [])),
            )
        )

    return techniques, by_id
