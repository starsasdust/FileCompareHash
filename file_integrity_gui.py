import os
import sys
import json
import hmac
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import base64


# Import secret key management module (no user input required after modification)
class SecretKeyManager:
    def __init__(self):
        self.BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.KEY_FILE = os.path.join(self.BASE_DIR, "hmac_key.json")
        self.KEY_LENGTH = 32  # (256-bit key) 32 bytes = 256 bits = strong key for HMAC
        self.SECRET_KEY = self.init_secret_key()

    def generate_key(self):
        return base64.urlsafe_b64encode(os.urandom(self.KEY_LENGTH)).decode()

    def save_key(self, encoded_key):
        with open(self.KEY_FILE, 'w') as f:
            json.dump({"secret_key": encoded_key}, f)

    def load_key(self):
        if not os.path.exists(self.KEY_FILE):
            encoded_key = self.generate_key()
            self.save_key(encoded_key)
            return encoded_key
        else:
            with open(self.KEY_FILE, 'r') as f:
                data = json.load(f)
                return data["secret_key"]

    def init_secret_key(self):
        encoded = self.load_key()
        return base64.urlsafe_b64decode(encoded)


# File Integrity Verification GUI
class FileIntegrityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Verification Tool")
        self.root.geometry("800x600")

        self.key_manager = SecretKeyManager()
        self.SECRET_KEY = self.key_manager.SECRET_KEY

        self.selected_items = []  # Store selected files and directories
        self.output_dir = ""

        self.create_widgets()

    def create_widgets(self):
        # Create main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Create input area
        input_frame = ttk.LabelFrame(main_frame, text="Input Selection", padding="10")
        input_frame.pack(fill=tk.X, pady=5)

        # Button area
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=tk.X, pady=5)

        ttk.Button(button_frame, text="Select Directory", command=self.select_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Select File", command=self.select_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Select Multiple Files", command=self.select_multiple_files).pack(side=tk.LEFT,
                                                                                                        padx=5)
        ttk.Button(button_frame, text="Remove Selected", command=self.remove_selected).pack(side=tk.LEFT, padx=5)

        # Selected items list
        list_frame = ttk.Frame(input_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.item_listbox = tk.Listbox(list_frame, height=6)
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.item_listbox.yview)
        self.item_listbox.configure(yscrollcommand=scrollbar.set)

        self.item_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Output directory selection
        output_frame = ttk.LabelFrame(main_frame, text="Output Directory", padding="10")
        output_frame.pack(fill=tk.X, pady=5)

        self.output_var = tk.StringVar()
        ttk.Entry(output_frame, textvariable=self.output_var, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True,
                                                                             padx=5)
        ttk.Button(output_frame, text="Browse", command=self.select_output_dir).pack(side=tk.LEFT, padx=5)

        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)

        ttk.Button(action_frame, text="Generate Hashes", command=self.generate_hashes).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Verify Hashes", command=self.verify_hashes).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Generate New Key", command=self.generate_new_key).pack(side=tk.LEFT, padx=5)

        # Status and output area
        output_frame = ttk.LabelFrame(main_frame, text="Output Information", padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.output_text = ScrolledText(output_frame, wrap=tk.WORD, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)

        # Configure text tags for color coding
        self.output_text.tag_config("red", foreground="red")
        self.output_text.tag_config("green", foreground="green")
        self.output_text.tag_config("yellow", foreground="gold")

        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Select Directory")
        if directory:
            self.selected_items.append(("dir", directory))
            self.item_listbox.insert(tk.END, f"Directory: {directory}")
            self.update_status(f"Added directory: {directory}")

    def select_file(self):
        file = filedialog.askopenfilename(title="Select File")
        if file:
            self.selected_items.append(("file", file))
            self.item_listbox.insert(tk.END, f"File: {file}")
            self.update_status(f"Added file: {file}")

    def select_multiple_files(self):
        files = filedialog.askopenfilenames(title="Select Multiple Files")
        for file in files:
            self.selected_items.append(("file", file))
            self.item_listbox.insert(tk.END, f"File: {file}")
        self.update_status(f"Added {len(files)} files")

    def remove_selected(self):
        selected_indices = self.item_listbox.curselection()
        if not selected_indices:
            messagebox.showinfo("Notice", "Please select items to remove first")
            return

            # Delete from back to front to avoid index change issues
        for i in sorted(selected_indices, reverse=True):
            del self.selected_items[i]
            self.item_listbox.delete(i)

        self.update_status("Removed selected items")

    def select_output_dir(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_dir = directory
            self.output_var.set(directory)
            self.update_status(f"Output directory set to: {directory}")

    def update_status(self, message, tag="normal"):
        """Update status bar and append message to output text with optional color tag"""
        self.status_var.set(message)
        self.output_text.insert(tk.END, message + "\n", tag)
        self.output_text.see(tk.END)

    def hash_file(self, filepath):
        h = hmac.new(self.SECRET_KEY, digestmod=hashlib.sha256)
        with open(filepath, 'rb') as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def generate_hashes(self):
        if not self.selected_items:
            messagebox.showinfo("Notice", "Please select files or directories first")
            return

        if not self.output_dir:
            messagebox.showinfo("Notice", "Please select an output directory")
            return

        file_hashes = {}
        self.output_text.delete(1.0, tk.END)
        self.update_status("Starting hash generation...")

        try:
            os.makedirs(self.output_dir, exist_ok=True)

            for item_type, path in self.selected_items:
                if item_type == "file":
                    filename = os.path.basename(path)
                    file_hash = self.hash_file(path)
                    file_hashes[filename] = file_hash
                    self.update_status(f"Hashed file: {filename}")
                else:  # directory
                    for root, _, files in os.walk(path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            file_hash = self.hash_file(filepath)
                            file_hashes[file] = file_hash
                            self.update_status(f"Hashed file: {file}")

            # Calculate overall hash
            combined_hmac = hmac.new(self.SECRET_KEY, digestmod=hashlib.sha256)
            for h in sorted(file_hashes.values()):
                combined_hmac.update(h.encode())
            file_hashes["overall_hash"] = combined_hmac.hexdigest()

            # Save hashes to JSON file
            output_path = os.path.join(self.output_dir, "hashes.json")
            with open(output_path, 'w') as f:
                json.dump(file_hashes, f, indent=4)

            self.update_status(f"Hashes saved to: {output_path}")
            messagebox.showinfo("Success", f"Successfully generated hashes and saved to {output_path}")

        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Error generating hashes: {str(e)}")

    def verify_hashes(self):
        if not self.selected_items:
            messagebox.showinfo("Notice", "Please select files or directories to verify first")
            return

        if not self.output_dir:
            messagebox.showinfo("Notice", "Please select a directory containing hash files")
            return

        hash_json_path = os.path.join(self.output_dir, "hashes.json")
        if not os.path.exists(hash_json_path):
            messagebox.showerror("Error", f"Hash file not found: {hash_json_path}")
            return

        self.output_text.delete(1.0, tk.END)
        self.update_status("Starting hash verification...")

        try:
            # Load stored hashes
            with open(hash_json_path, 'r') as f:
                stored_hashes = json.load(f)

            # Display overall hash (if available)
            overall_hash = stored_hashes.pop("overall_hash", None)
            if overall_hash:
                self.update_status(f"Stored overall hash: {overall_hash}")

            verification_results = []
            files_verified = 0
            modified_files = 0
            missing_hash_files = 0

            for item_type, path in self.selected_items:
                if item_type == "file":
                    filename = os.path.basename(path)
                    computed_hash = self.hash_file(path)
                    expected_hash = stored_hashes.get(filename)

                    self.update_status(f"\nFile: {filename}")
                    self.update_status(f"  Expected hash: {expected_hash}")
                    self.update_status(f"  Computed hash: {computed_hash}")

                    if expected_hash is None:
                        result = "NO (no stored hash found)"
                        verification_results.append((filename, False, "missing"))
                        missing_hash_files += 1
                        self.update_status(f"Verification result for {filename}: {result}", "yellow")
                    elif computed_hash == expected_hash:
                        result = "YES"
                        verification_results.append((filename, True, "match"))
                        self.update_status(f"Verification result for {filename}: {result}", "green")
                    else:
                        result = "NO (hash mismatch)"
                        verification_results.append((filename, False, "modified"))
                        modified_files += 1
                        self.update_status(f"Verification result for {filename}: {result}", "red")

                    files_verified += 1

                else:  # directory
                    for root, _, files in os.walk(path):
                        for file in files:
                            filepath = os.path.join(root, file)
                            computed_hash = self.hash_file(filepath)
                            expected_hash = stored_hashes.get(file)

                            self.update_status(f"\nFile: {file}")
                            self.update_status(f"  Expected hash: {expected_hash}")
                            self.update_status(f"  Computed hash: {computed_hash}")

                            if expected_hash is None:
                                result = "NO (no stored hash found)"
                                verification_results.append((file, False, "missing"))
                                missing_hash_files += 1
                                self.update_status(f"Verification result for {file}: {result}", "yellow")
                            elif computed_hash == expected_hash:
                                result = "YES"
                                verification_results.append((file, True, "match"))
                                self.update_status(f"Verification result for {file}: {result}", "green")
                            else:
                                result = "NO (hash mismatch)"
                                verification_results.append((file, False, "modified"))
                                modified_files += 1
                                self.update_status(f"Verification result for {file}: {result}", "red")

                            files_verified += 1

            # Display summary results with colors
            passed = sum(1 for _, result, _ in verification_results if result)
            self.update_status(f"\nVerification summary:")
            self.update_status(f"  Total files processed: {files_verified}")
            self.update_status(f"  Passed: {passed}", "green")
            self.update_status(f"  Failed due to modification: {modified_files}", "red")
            self.update_status(f"  Failed due to missing hash: {missing_hash_files}", "yellow")

            if passed == files_verified and files_verified > 0:
                messagebox.showinfo("Verification Success", "All files passed verification!")
            elif files_verified == 0:
                messagebox.showinfo("Notice", "No files found to verify")
            else:
                # Create a more detailed message
                detail_msg = f"Verification results:\n\n" \
                             f"Passed: {passed}\n" \
                             f"Failed due to modification: {modified_files}\n" \
                             f"Failed due to missing hash: {missing_hash_files}"
                messagebox.showwarning("Verification Failed", detail_msg)

        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            messagebox.showerror("Error", f"Error verifying hashes: {str(e)}")

    def generate_new_key(self):
        """Generate new key and update storage"""
        if messagebox.askyesno("Confirm",
                               "Generating a new key will invalidate previously generated hashes. Are you sure you want to continue?"):
            try:
                encoded_key = self.key_manager.generate_key()
                self.key_manager.save_key(encoded_key)
                self.SECRET_KEY = base64.urlsafe_b64decode(encoded_key)
                self.update_status(f"New key generated:\n{encoded_key}")
                messagebox.showinfo("Success", "New key has been generated")
            except Exception as e:
                self.update_status(f"Error generating new key: {str(e)}")
                messagebox.showerror("Error", f"Error generating new key: {str(e)}")


# Main program entry
def main():
    root = tk.Tk()
    app = FileIntegrityGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()