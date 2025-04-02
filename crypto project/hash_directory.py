import os
import hmac
import hashlib
import json
from secret_key import SECRET_KEY
""""
------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
HEY TEAM!!!

So heres what I put together for Part 1 of our project. Basically, I made a Python script that can hash either a single file or an entire folder full of files. 
When you run it, it asks you where the files are that you want to hash, and where you want the output to go. You dont need to create the output folder yourself — the script will make it for you if it doesnt exist. Super easy.

For each file, it creates a secure hash using HMAC with SHA-256 (dont worry, its a solid method). All the hashes get saved in one single JSON file called hashes.json. 
That file includes the hash for each file, plus an “overall hash” which is just a combined hash of all the individual ones — kind of like a fingerprint for the entire directory. 
If even one file changes later, that overall hash will change too.

The script also uses a secret key for generating the HMACs, and I set it up to be pretty flexible. 
The first time you run the script, it generates a secure random key and saves it in a file called hmac_key.json. From then on, it keeps using that same key unless you choose to regenerate it. 
When you start the script, it'll ask if you want to make a new key — just say no unless youre doing testing or want to reset everything.

All of that secret key stuff is handled in a separate file called secret_key.py, so its reusable and stays clean. 
Both the hashing script and your verification script can import the same key from that file, so we stay consistent.

Let me know when you're ready to work on Part 2 — I can help with that too if you want. Basically, you'll just load the hashes.json, rehash the files, and check if the hashes match. 
The script is already set up in a way that makes it really easy to plug into.

XU if you need help with UI also let me know

Thank you Let me know if you run into anything!

PS: for testing when in putting file they jshould be formated this way doesnt have to look exctly like mine tho 
C:\Users\18628\OneDrive\Desktop\test this is all subjective to directory you are using, need to improve the error handeling i tried below  i will work on
-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
"""

# Hash a single file using HMAC-SHA256 and our secret key
def hash_file(filepath):
    h = hmac.new(SECRET_KEY, digestmod=hashlib.sha256)
    with open(filepath, 'rb') as f:
        # Read the file in chunks in case it's large
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest() # returns the hash as a hex string

# Go through the file or directory and create hashes for everything inside
def generate_file_hashes(input_path):
    file_hashes = {}

    if os.path.isfile(input_path):
        # If it's a single file, just hash it and add to our dictionary
        filename = os.path.basename(input_path)
        file_hashes[filename] = hash_file(input_path)
    else:
        # If it's a directory, walk through all the files
        for root, _, files in os.walk(input_path):
            for file in files:
                full_path = os.path.join(root, file)
                file_hashes[file] = hash_file(full_path)

    return file_hashes # dictionary of {filename: file_hash}

# Save the hashes (plus an overall hash) into a JSON file
def write_hashes_to_json(file_hashes, output_dir):
    combined_hmac = hmac.new(SECRET_KEY, digestmod=hashlib.sha256)
    for h in sorted(file_hashes.values()):
        combined_hmac.update(h.encode())
    # Add the overall hash to the dictionary
    file_hashes["overall_hash"] = combined_hmac.hexdigest()
    # Save the whole dictionary as JSON in the output directory
    output_path = os.path.join(output_dir, "hashes.json")
    with open(output_path, 'w') as f:
        json.dump(file_hashes, f, indent=4)

    print(f"\nHashes saved to: {output_path}")

# Just a little helper to clean up paths (sometimes python does like when you input path certain way tried fix that so no confusion)
""""
-------------------------------------------------------------------------------------------------------------------
xu this function is not really needed i thought it can maybe help with the UI but if we dont need it we can delete it let me know if any question 
-----------------------------------------------------------------------------------------------------------------------------------------------
"""
def clean_path(path):
    return os.path.normpath(path.strip().replace('\\', '/'))

def main():
#error handeling needs work will fix 
    try:
        input_path = clean_path(input("Enter the path to the file or directory you want to hash: "))
        output_dir = clean_path(input("Enter the path where you want to save the hash output: "))

        if not os.path.exists(input_path):
            print(f"Error: The input path '{input_path}' does not exist.")
            return

        os.makedirs(output_dir, exist_ok=True)
        print(f"Output directory set to: {output_dir}")

        file_hashes = generate_file_hashes(input_path)
        write_hashes_to_json(file_hashes, output_dir)

    except Exception as e:
        print(f"\n nAn unexpected error occurred: {e}")

if __name__ == '__main__':
    main()