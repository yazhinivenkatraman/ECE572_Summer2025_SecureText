import json
import os
import base64
import bcrypt
import hashlib

"""
Migration script to make 
plaintext passwords -> SHA256, then salt + bcrypt
SHA256 hashed passwords -> salt and bcrypt
Already migrated -> Skip the user creds
"""
with open("users.json", "r") as f:
    users = json.load(f)

updated = 0
for username, data in users.items():
    if "salt" not in data:
        original_password = data['password']
        # Detect if it's already a SHA-256 hash (64 hex characters)
        if len(original_password) == 64 and all(c in '0123456789abcdef' for c in original_password):
            print(f"Migrating SHA-256 hash for user: {username}")
        # Else it is a plaintext password user
        else:
            print(f"Migrating plaintext password for user: {username}")
            original_password = hashlib.sha256(original_password.encode()).hexdigest()

        salt = base64.b64encode(os.urandom(16)).decode()
        salted_pwd = original_password + salt
        hashed = bcrypt.hashpw(salted_pwd.encode(), bcrypt.gensalt()).decode()

        data['password'] = hashed
        data['salt'] = salt
        updated += 1

with open("users.json", "w") as f:
    json.dump(users, f, indent=2)

print(f"Migrated {updated} users to salted bcrypt format.")
