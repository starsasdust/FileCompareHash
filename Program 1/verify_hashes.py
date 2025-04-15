import os
import sys
import json
import hmac
import hashlib
from secret_key import SECRET_KEY  # Uses the same secret key

# Compute the HMAC-SHA256 hash for the given file
def hash_file(filepath):
    h = hmac.new(SECRET_KEY, digestmod=hashlib.sha256)
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# Verify files by comparing computed hashes with stored ones, with added debug info
def verify_files(input_dir, hash_output_dir):
    # Build path to the JSON file containing stored hashes
    hash_json_path = os.path.join(hash_output_dir, "hashes.json")
    if not os.path.exists(hash_json_path):
        print(f"Error: Hash file not found in {hash_output_dir}")
        sys.exit(1)
    
    # Load the stored hashes
    with open(hash_json_path, 'r') as f:
        stored_hashes = json.load(f)
    
    # Optionally print the overall hash (if available)
    overall_hash = stored_hashes.pop("overall_hash", None)
    if overall_hash:
        print(f"Stored overall hash: {overall_hash}")
    
    files_found = False
    # Walk through the input directory
    for root, _, files in os.walk(input_dir):
        for file in files:
            files_found = True
            filepath = os.path.join(root, file)
            computed_hash = hash_file(filepath)
            expected_hash = stored_hashes.get(file)
            
            # Debug prints: show both expected and computed hash
            print(f"\nFile: {file}")
            print(f"  Expected hash: {expected_hash}")
            print(f"  Computed hash: {computed_hash}")
            
            if expected_hash is None:
                result = "NO (no stored hash found)"
            elif computed_hash == expected_hash:
                result = "YES"
            else:
                result = "NO"
            print(f"Verification result for {file}: {result}")
    
    if not files_found:
        print("No files were found in the input directory.")

# Main entry point: handle command-line args and run verification
def main():
    if len(sys.argv) != 3:
        print("Usage: python verify_hashes.py <directory1> <directory2>")
        sys.exit(1)
    
    input_dir = sys.argv[1]
    hash_output_dir = sys.argv[2]
    
    if not os.path.exists(input_dir):
        print(f"Error: Input directory '{input_dir}' does not exist.")
        sys.exit(1)
    
    if not os.path.exists(hash_output_dir):
        print(f"Error: Hash output directory '{hash_output_dir}' does not exist.")
        sys.exit(1)
    
    verify_files(input_dir, hash_output_dir)

if __name__ == '__main__':
    main()
