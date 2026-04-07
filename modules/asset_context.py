import json

def load_assets(path="data/assets.json"):
    with open(path) as f:
        return json.load(f)

def get_asset_context(ip, asset_db):
    return asset_db.get(ip, {"name": "unknown", "criticality": 1})
