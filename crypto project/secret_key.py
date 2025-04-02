import os
import base64
import json

# This is the file that stores our secret key so it's persistent between runs
KEY_FILE = "hmac_key.json"
KEY_LENGTH = 32  # (256-bit key) 32 bytes = 256 bits = strong key for HMAC

# This function creates a new random key and encodes it in base64 (so it's easy to store/share)
def generate_key():
    return base64.urlsafe_b64encode(os.urandom(KEY_LENGTH)).decode()


# This saves the encoded key to our key file in JSON format
def save_key(encoded_key):
    with open(KEY_FILE, 'w') as f:
        json.dump({"secret_key": encoded_key}, f)


# This checks if we already have a key saved
# If not, it generates one and saves it
def load_key():
    if not os.path.exists(KEY_FILE):
        print("🔐 No existing key found. Generating new key...")
        encoded_key = generate_key()
        save_key(encoded_key)
        return encoded_key
    else:
        with open(KEY_FILE, 'r') as f:
            data = json.load(f)
            return data["secret_key"]

# This lets the user decide if they want to generate a new key
# (good for testing, resets, or security rotation)
def maybe_regenerate():
    choice = input("Do you want to generate a new key? (y/n): ").strip().lower()
    if choice == 'y':
        new_key = generate_key()
        save_key(new_key)
        print(f"\n✅ New key generated:\n{new_key}\n")
        return new_key
    else:
        return load_key()


# This is the actual secret key we use in our other scripts
# It's decoded back from base64 to raw bytes so HMAC can use it
encoded = maybe_regenerate()
SECRET_KEY = base64.urlsafe_b64decode(encoded)