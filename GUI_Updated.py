import os
import json
import hmac
import hashlib
import tkinter as tk
from tkinter import filedialog, ttk, messagebox
from tkinter.scrolledtext import ScrolledText
import base64


# ----------------------------
# Chris's work: Secret key management module (secret_key.py equivalent)
# ----------------------------
class SecretKeyManager:
    def __init__(self):
        self.BASE_DIR = os.path.dirname(os.path.abspath(__file__))
        self.KEY_FILE = os.path.join(self.BASE_DIR, "hmac_key.json")
        self.KEY_LENGTH = 32  # 256-bit key
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
        with open(self.KEY_FILE, 'r') as f:
            data = json.load(f)
            return data.get("secret_key")

    def init_secret_key(self):
        encoded = self.load_key()
        return base64.urlsafe_b64decode(encoded)


# ----------------------------
# Xu's work: GUI integration for hashing and JSON output
# File: combines UI with hashing logic
# ----------------------------
class FileIntegrityGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Verification Tool")
        self.root.geometry("800x600")

        self.key_manager = SecretKeyManager()
        self.SECRET_KEY = self.key_manager.SECRET_KEY

        self.selected_items = []
        self.output_dir = ""
        self.use_default_dir_var = tk.BooleanVar(value=False)  # Unchecked by default for safety

        self.create_widgets()

    def create_widgets(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Input Selection
        input_frame = ttk.LabelFrame(main_frame, text="Input Selection", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        button_frame = ttk.Frame(input_frame)
        button_frame.pack(fill=tk.X, pady=5)
        ttk.Button(button_frame, text="Select Directory", command=self.select_directory).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Select File", command=self.select_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Select Multiple Files", command=self.select_multiple_files).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Remove Selected", command=self.remove_selected).pack(side=tk.LEFT, padx=5)
        list_frame = ttk.Frame(input_frame)
        list_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.item_listbox = tk.Listbox(list_frame, height=6)
        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.item_listbox.yview)
        self.item_listbox.configure(yscrollcommand=scrollbar.set)
        self.item_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Output Directory Selection
        output_frame = ttk.LabelFrame(main_frame, text="Output Directory", padding="10")
        output_frame.pack(fill=tk.X, pady=5)
        ttk.Checkbutton(
            output_frame,
            text="Use script directory as output location",
            variable=self.use_default_dir_var,
            command=self.toggle_output_dir_selection
        ).pack(side=tk.LEFT, padx=5)
        self.output_var = tk.StringVar()
        self.output_entry = ttk.Entry(output_frame, textvariable=self.output_var, width=40)
        self.output_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        self.browse_button = ttk.Button(output_frame, text="Browse", command=self.select_output_dir)
        self.browse_button.pack(side=tk.LEFT, padx=5)

        # Actions
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        ttk.Button(action_frame, text="Generate Hashes", command=self.generate_hashes).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Verify Hashes", command=self.verify_hashes).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Generate New Key", command=self.generate_new_key).pack(side=tk.LEFT, padx=5)

        # Output Information
        output_info = ttk.LabelFrame(main_frame, text="Output Information", padding="10")
        output_info.pack(fill=tk.BOTH, expand=True, pady=5)
        self.output_text = ScrolledText(output_info, wrap=tk.WORD, height=10)
        self.output_text.pack(fill=tk.BOTH, expand=True)
        # Xu's work: 16-point font and styling
        self.output_text.configure(font=("TkDefaultFont", 16))
        self.output_text.tag_config("normal", font=("TkDefaultFont", 16))
        self.output_text.tag_config("green", foreground="green", font=("TkDefaultFont", 16))
        self.output_text.tag_config("yellow", foreground="gold", font=("TkDefaultFont", 16))
        self.output_text.tag_config("red", foreground="red", font=("TkDefaultFont", 16, "bold"))

        # Status Bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.toggle_output_dir_selection()

    # ----------------------------
    # Xu's work: Toggle output directory selection
    # ----------------------------
    def toggle_output_dir_selection(self):
        if self.use_default_dir_var.get():
            self.output_entry.configure(state='disabled')
            self.browse_button.configure(state='disabled')
            self.output_dir = self.key_manager.BASE_DIR
            self.output_var.set(self.output_dir)
            self.update_status(f"Using script directory for output: {self.output_dir}")
        else:
            self.output_entry.configure(state='normal')
            self.browse_button.configure(state='normal')
            self.output_var.set("")
            self.output_dir = ""
            self.update_status("Please select an output directory")

    # ----------------------------
    # Xu's work: File selection handlers
    # ----------------------------
    def select_directory(self):
        d = filedialog.askdirectory(title="Select Directory")
        if d:
            self.selected_items.append(("dir", d))
            self.item_listbox.insert(tk.END, f"Directory: {d}")
            self.update_status(f"Added directory: {d}")

    def select_file(self):
        fpath = filedialog.askopenfilename(title="Select File")
        if fpath:
            self.selected_items.append(("file", fpath))
            self.item_listbox.insert(tk.END, f"File: {fpath}")
            self.update_status(f"Added file: {fpath}")

    def select_multiple_files(self):
        files = filedialog.askopenfilenames(title="Select Multiple Files")
        for fpath in files:
            self.selected_items.append(("file", fpath))
            self.item_listbox.insert(tk.END, f"File: {fpath}")
        self.update_status(f"Added {len(files)} files")

    def remove_selected(self):
        idxs = self.item_listbox.curselection()
        if not idxs:
            messagebox.showinfo("Notice", "Please select items to remove")
            return
        for i in sorted(idxs, reverse=True):
            del self.selected_items[i]
            self.item_listbox.delete(i)
        self.update_status("Removed selected items")

    # ----------------------------
    # Xu's work: Output directory browse handler (missing previously)
    # ----------------------------
    def select_output_dir(self):
        directory = filedialog.askdirectory(title="Select Output Directory")
        if directory:
            self.output_dir = directory
            self.output_var.set(directory)
            self.update_status(f"Output directory set to: {directory}")

    # ----------------------------
    # Xu's work: Status output helper
    # ----------------------------
    def update_status(self, message, tag="normal"):
        self.status_var.set(message)
        self.output_text.insert(tk.END, message + "\n", tag)
        self.output_text.see(tk.END)

    # ----------------------------
    # Chris's work: Compute HMAC-SHA256 for a file
    # ----------------------------
    def hash_file(self, filepath):
        h = hmac.new(self.SECRET_KEY, digestmod=hashlib.sha256)
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()

    # ----------------------------
    # Chris's work: Generate and save hashes.json
    # ----------------------------
    def generate_hashes(self):
        if self.use_default_dir_var.get():
            self.output_dir = self.key_manager.BASE_DIR
            self.output_var.set(self.output_dir)
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
            for typ, path in self.selected_items:
                if typ == "file":
                    name = os.path.basename(path)
                    file_hashes[name] = self.hash_file(path)
                    self.update_status(f"Hashed file: {name}")
                else:
                    for root, _, files in os.walk(path):
                        for name in files:
                            fp = os.path.join(root, name)
                            file_hashes[name] = self.hash_file(fp)
                            self.update_status(f"Hashed file: {name}")
            combo = hmac.new(self.SECRET_KEY, digestmod=hashlib.sha256)
            for hval in sorted(file_hashes.values()):
                combo.update(hval.encode())
            file_hashes["overall_hash"] = combo.hexdigest()
            out_path = os.path.join(self.output_dir, "hashes.json")
            with open(out_path, 'w') as jf:
                json.dump(file_hashes, jf, indent=4)
            self.update_status(f"Hashes saved to: {out_path}")
            messagebox.showinfo("Success", f"Hashes saved to {out_path}")
        except Exception as e:
            self.update_status(f"Error: {e}", "red")
            messagebox.showerror("Error", f"Error generating hashes: {e}")

    # ----------------------------
    # Nathan's work: Verify hashes and report
    # ----------------------------
    def verify_hashes(self):
        if self.use_default_dir_var.get():
            self.output_dir = self.key_manager.BASE_DIR
            self.output_var.set(self.output_dir)
        if not self.selected_items:
            messagebox.showinfo("Notice", "Please select items to verify")
            return
        if not self.output_dir:
            messagebox.showinfo("Notice", "Please select a directory containing hashes")
            return
        hash_file_path = os.path.join(self.output_dir, "hashes.json")
        if not os.path.exists(hash_file_path):
            messagebox.showerror("Error", f"Hash file not found: {hash_file_path}")
            return
        self.output_text.delete(1.0, tk.END)
        self.update_status("Starting verification...")
        try:
            with open(hash_file_path, 'r') as jf:
                stored = json.load(jf)
            overall = stored.pop("overall_hash", None)
            if overall:
                self.update_status(f"Stored overall hash: {overall}")
            results = []
            total = 0
            for typ, path in self.selected_items:
                if typ == "file":
                    name = os.path.basename(path)
                    comp = self.hash_file(path)
                    exp = stored.get(name)
                    self._log_verification(name, exp, comp, results)
                    total += 1
                else:
                    for root, _, files in os.walk(path):
                        for name in files:
                            fp = os.path.join(root, name)
                            comp = self.hash_file(fp)
                            exp = stored.get(name)
                            self._log_verification(name, exp, comp, results)
                            total += 1
            passed = sum(1 for _, ok, _ in results if ok)
            modified = sum(1 for _, _, tag in results if tag=="modified")
            missing = sum(1 for _, _, tag in results if tag=="missing")
            self.update_status(f"\nSummary: {total} files, Passed: {passed}")
            self.update_status(f"Failed modified: {modified}", "red")
            self.update_status(f"Failed missing: {missing}", "yellow")
            if passed == total and total > 0:
                messagebox.showinfo("Success", "All files verified")
            elif total == 0:
                messagebox.showinfo("Notice", "No files to verify")
            else:
                messagebox.showwarning("Verification results", f"Passed: {passed}, Modified: {modified}, Missing: {missing}")
        except Exception as e:
            self.update_status(f"Error: {e}", "red")
            messagebox.showerror("Error", f"Error verifying hashes: {e}")

    def _log_verification(self, name, exp, comp, results):
        self.update_status(f"\nFile: {name}")
        self.update_status(f"  Expected: {exp}")
        self.update_status(f"  Computed: {comp}")
        if exp is None:
            msg, tag, flag = "NO (no stored hash)", "yellow", "missing"
        elif comp == exp:
            msg, tag, flag = "YES", "green", "match"
        else:
            msg, tag, flag = "NO (hash mismatch)", "red", "modified"
        results.append((name, flag == "match", flag))
        self.update_status(f"Verification result: {msg}", tag)

    # ----------------------------
    # Xu's work: GUI key regeneration integration
    # ----------------------------
    def generate_new_key(self):
        if messagebox.askyesno("Confirm", "Invalidate old hashes and generate new key?"):
            try:
                new_encoded = self.key_manager.generate_key()
                self.key_manager.save_key(new_encoded)
                self.SECRET_KEY = base64.urlsafe_b64decode(new_encoded)
                self.update_status(f"New key generated: {new_encoded}")
                messagebox.showinfo("Success", "New key generated")
            except Exception as e:
                self.update_status(f"Error: {e}", "red")
                messagebox.showerror("Error", f"Error generating key: {e}")

# Main entry
def main():
    root = tk.Tk()
    app = FileIntegrityGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main()
