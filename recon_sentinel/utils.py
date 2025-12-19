import hashlib
from pathlib import Path
import json

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, sort_keys=True)

def read_json(path: Path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
