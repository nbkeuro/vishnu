import hashlib, json

with open("password") as f:
    stored = json.load(f)["password"]

password_try = "Br_3339"
hashed = hashlib.sha256(password_try.encode()).hexdigest()

print("Expected :", stored)
print("Entered  :", hashed)
print("Match?   :", stored == hashed)

