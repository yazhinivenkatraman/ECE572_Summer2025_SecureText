import hashlib
import json
import time
import bcrypt


# Load users.json file containing SHA-256 hashes (no salt)
with open("users.json", "r") as f: 
    users = json.load(f)

# Sample password dictionary
dictionary = ["password", "123456", "qwerty", "test@123", "hello123", "admin"]

# Loop through users to check each hash against dictionary
for username, details in users.items():
    start = time.time()
    stored_hash = details["password"]
    
    print(f"\nChecking for user: {username}")
    for word in dictionary:
        hashed = hashlib.sha256(word.encode()).hexdigest()
        if hashed == stored_hash:
            print(f"Password for user '{username}' is: {word}")
            end = time.time()
            print("Time taken for finding SHA-256 hashed password is " + str(float(end - start)) + " seconds\n")
            break
    else:
        print("Password not found in dictionary.")

print("\n\n\n--- Testing dictionary attack on salted bcrypt hashes ---")

for username, details in users.items():
    if "salt" not in details:
        continue  # Skip SHA-256 users

    stored_hash = details["password"]
    salt = details["salt"]  # stored base64-encoded salt

    print(f"\nTrying dictionary attack on user: {username}")
    found = False
    for word in dictionary:
        salted_password = word + salt
        if bcrypt.checkpw(salted_password.encode(), stored_hash.encode()):
            print(f"Password for user '{username}' is: {word}")
            found = True
            break

    if not found:
        print("Dictionary attack failed: Salting defeated the attack.")


print("\n\n\n--- Simulating Rainbow Table Attack ---")

# Simulated rainbow table - precomputed SHA-256 hashes for common passwords
rainbow_table = {
    hashlib.sha256(word.encode()).hexdigest(): word for word in dictionary
}

for username, details in users.items():
    print(f"\nRainbow table attack on user: {username}")
    stored_hash = details["password"]
    if stored_hash in rainbow_table:
        print(f"Rainbow table matched! Password is: {rainbow_table[stored_hash]}")
    else:
        print("Rainbow table failed to crack the password.")