import tkinter as tk
from tkinter import messagebox, simpledialog
import secrets
import string
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import os

class PasswordManager:
    def __init__(self, master):
        self.master = master
        master.title("Password Manager")
        master.geometry("600x450")  

        
        self.bg_color = "#f0f0f0"  
        self.fg_color = "#333333"  
        self.button_bg = "#6200EE"  
        self.button_fg = "white"  
        self.entry_bg = "white"  
        self.entry_fg = "#333333" 
        self.highlight_color = "#00796B"

        master.configure(bg=self.bg_color)  

        self.master_password = None
        self.key = None
        self.passwords = {}
        self.password_file = "passwords.json"


        self.label_master = tk.Label(master, text="Enter Master Password:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 12))
        self.label_master.pack(pady=10)

        self.entry_master = tk.Entry(master, show="*", bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 12), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.entry_master.pack(fill=tk.X, padx=30) 

        self.button_login = tk.Button(master, text="Login", command=self.login, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 12), bd=0, padx=20, pady=5, relief=tk.FLAT)  
        self.button_login.pack(pady=20) 

        self.main_frame = tk.Frame(master, bg=self.bg_color) 
        self.main_frame.pack_forget()

        self.button_generate = tk.Button(self.main_frame, text="Generate Password", command=self.open_generator, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=15, pady=5, relief=tk.FLAT)
        self.button_generate.pack(pady=5)

        self.button_save = tk.Button(self.main_frame, text="Save Password", command=self.open_save_dialog, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=15, pady=5, relief=tk.FLAT)
        self.button_save.pack(pady=5)

        self.button_view = tk.Button(self.main_frame, text="View Passwords", command=self.view_passwords, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=15, pady=5, relief=tk.FLAT)
        self.button_view.pack(pady=5)

    def login(self):
        self.master_password = self.entry_master.get()

        if not self.master_password:
            messagebox.showerror("Error", "Master Password cannot be empty.")
            return

        self.key = self.derive_key(self.master_password)

        try:
            self.load_passwords()
        except FileNotFoundError:
            self.passwords = {}
        except Exception as e:
            messagebox.showerror("Error", f"Error loading passwords: {e}")
            self.passwords = {}

        self.entry_master.delete(0, tk.END)
        self.label_master.destroy()
        self.entry_master.destroy()
        self.button_login.destroy()

        self.main_frame.pack()

    def derive_key(self, password):
        password = password.encode()
        salt = b'salt_' 
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key

    def generate_password(self, length=16):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

    def open_generator(self):
        def generate_and_display():
            try:
                length = int(length_entry.get())
                if length <= 0:
                    raise ValueError("Length must be a positive integer.")
            except ValueError:
                messagebox.showerror("Error", "Invalid length.  Please enter a positive integer.")
                return

            new_password = self.generate_password(length)
            password_text.delete(1.0, tk.END)
            password_text.insert(tk.END, new_password)

        generator_window = tk.Toplevel(self.master)
        generator_window.title("Generate Password")
        generator_window.configure(bg=self.bg_color)  

        length_label = tk.Label(generator_window, text="Password Length:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        length_label.pack(pady=5)

        length_entry = tk.Entry(generator_window, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        length_entry.insert(0, "16")
        length_entry.pack(fill=tk.X, padx=20)

        generate_button = tk.Button(generator_window, text="Generate", command=generate_and_display, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        generate_button.pack(pady=10)

        password_text = tk.Text(generator_window, height=2, width=40, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        password_text.pack(pady=10)

    def encrypt(self, data):
        f = Fernet(self.key)
        return f.encrypt(data.encode()).decode()

    def decrypt(self, data):
        f = Fernet(self.key)
        return f.decrypt(data.encode()).decode()

    def open_save_dialog(self):
        def save_password():
            site_name = site_entry.get()
            password = password_entry.get()

            if not site_name or not password:
                messagebox.showerror("Error", "Site Name and Password cannot be empty.")
                return

            encrypted_password = self.encrypt(password)
            self.passwords[site_name] = encrypted_password
            self.save_passwords()
            messagebox.showinfo("Success", "Password saved successfully!")
            save_window.destroy()


        save_window = tk.Toplevel(self.master)
        save_window.title("Save Password")
        save_window.configure(bg=self.bg_color)

        site_label = tk.Label(save_window, text="Site Name:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        site_label.pack(pady=5)
        site_entry = tk.Entry(save_window, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        site_entry.pack(fill=tk.X, padx=20)

        password_label = tk.Label(save_window, text="Password:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        password_label.pack(pady=5)
        password_entry = tk.Entry(save_window, show="*", bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        password_entry.pack(fill=tk.X, padx=20)

        save_button = tk.Button(save_window, text="Save", command=save_password, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        save_button.pack(pady=10)

    def load_passwords(self):
        with open(self.password_file, "r") as f:
            data = json.load(f)
            self.passwords = {str(k): v for k, v in data.items()}

    def save_passwords(self):
        with open(self.password_file, "w") as f:
            json.dump(self.passwords, f)

    def view_passwords(self):
        view_window = tk.Toplevel(self.master)
        view_window.title("View Passwords")
        view_window.configure(bg=self.bg_color) 

        if not self.passwords:
            messagebox.showinfo("Info", "No passwords saved yet.")
            return

        listbox = tk.Listbox(view_window, width=50, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        listbox.pack(padx=20, pady=10)

        for site in self.passwords:
            listbox.insert(tk.END, site)

        def show_password():
            try:
                selected_site = listbox.get(listbox.curselection())
                encrypted_password = self.passwords[selected_site]
                decrypted_password = self.decrypt(encrypted_password)
                messagebox.showinfo("Password", f"Password for {selected_site}: {decrypted_password}")
            except tk.TclError:
                messagebox.showerror("Error", "No site selected.")
            except Exception as e:
                messagebox.showerror("Error", f"Error decrypting password: {e}")

        show_button = tk.Button(view_window, text="Show Password", command=show_password, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        show_button.pack(pady=10)


root = tk.Tk()
my_gui = PasswordManager(root)
root.mainloop()