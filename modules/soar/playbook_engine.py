from playbooks import defense_evasion, lateral_movement, persistence, credential_access, reconnaissance, collection

PLAYBOOK_MAP = {
    "defense_evasion_response": defense_evasion.run,
    "lateral_movement_response": lateral_movement.run,
    "persistence_response": persistence.run,
    "credential_access_response": credential_access.run,
    "reconnaissance_response": reconnaissance.run,
    "collection_response": collection.run,
}

def execute_playbook(playbook_name, alert):
    playbook_func = PLAYBOOK_MAP.get(playbook_name)

    if not playbook_func:
        return ["No playbook available"]

    return playbook_func(alert)
