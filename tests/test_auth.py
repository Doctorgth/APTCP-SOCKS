import pytest
import os
import tempfile
import json

from common.config import load_users_jsonl, validate_credentials

def test_jsonl_user_loading_and_validation():
    with tempfile.NamedTemporaryFile('w+', delete=False, suffix='.jsonl') as tf:
        tf.write(json.dumps({"username": "user1", "password": "secret1"}) + "\n")
        tf.write(json.dumps({"username": "user2", "password": "secret2"}) + "\n")
        temp_name = tf.name

    try:
        users = load_users_jsonl(temp_name)
        assert len(users) == 2
        assert validate_credentials(users, "user1", "secret1") is True
        assert validate_credentials(users, "user1", "wrongpass") is False
        assert validate_credentials(users, "nonexistent", "secret1") is False
    finally:
        os.remove(temp_name)