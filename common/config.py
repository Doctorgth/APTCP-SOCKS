import json
import os
from typing import Dict, Any

def load_json_config(path: str) -> Dict[str, Any]:
    """Loads a JSON configuration file."""
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def load_users_jsonl(path: str) -> Dict[str, str]:
    """
    Loads username/password pairs from a JSONL file.
    Each line must be a JSON object: {"username": "...", "password": "..."}
    """
    users = {}
    if not os.path.exists(path):
        return users
    with open(path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            data = json.loads(line)
            if "username" in data and "password" in data:
                users[data["username"]] = str(data["password"])
    return users

def validate_credentials(users: Dict[str, str], username: str, password: str) -> bool:
    """Validates given username and password against users dictionary."""
    return users.get(username) == password