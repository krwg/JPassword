import tkinter as tk
from tkinter import messagebox, simpledialog, ttk  
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
        master.title("JPassword")
        master.geometry("500x400")

        
        self.bg_color = "#f0f0f0"
        self.fg_color = "#333333"
        self.button_bg = "#6200EE"
        self.button_fg = "white"
        self.entry_bg = "white"
        self.entry_fg = "#333333"
        self.highlight_color = "#00796B"
        self.error_color = "red"
        self.success_color = "green"

        master.configure(bg=self.bg_color)

        
        self.profiles_file = "profiles.json"
        self.current_profile = None
        self.profiles = {}
        self.master_password = None
        self.key = None
        self.default_password_length = 16
        self.include_symbols = True

        
        self.load_profiles()
        
        self.profile_var = tk.StringVar(self.master)  
        if not self.profiles:
            self.create_default_profile() 

        self.setup_login_screen()  

    def create_default_profile(self):
      """Создает профиль по умолчанию, если их нет."""
      profile_name = "Default"
      if not self.profiles:
          self.profiles[profile_name] = {
              "key": None,
              "password_file": f"{profile_name}_passwords.json"
          }
          self.save_profiles()
          self.current_profile = profile_name  
          self.profile_var.set(profile_name) 
          
    def setup_login_screen(self):
        
        self.login_frame = tk.Frame(self.master, bg=self.bg_color)
        self.login_frame.pack(expand=True, fill="both")

        self.label_profile = tk.Label(self.login_frame, text="Select Profile:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 12))
        self.label_profile.pack(pady=5)

        
        self.profile_dropdown = ttk.Combobox(self.login_frame, textvariable=self.profile_var, values=list(self.profiles.keys()), font=("Roboto", 12))
        self.profile_dropdown.pack(pady=5, padx=20, fill=tk.X)
        self.profile_dropdown.set(self.current_profile if self.current_profile else list(self.profiles.keys())[0] if self.profiles else "") 

        self.label_master = tk.Label(self.login_frame, text="Enter Master Password:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 12))
        self.label_master.pack(pady=5)

        self.entry_master = tk.Entry(self.login_frame, show="*", bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 12), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.entry_master.pack(fill=tk.X, padx=30, pady=5)

        self.button_login = tk.Button(self.login_frame, text="Login", command=self.login, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 12), bd=0, padx=20, pady=5, relief=tk.FLAT)
        self.button_login.pack(pady=10)

        
        self.button_manage_profiles = tk.Button(self.login_frame, text="Manage Profiles", command=self.open_profile_management, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=15, pady=5, relief=tk.FLAT)
        self.button_manage_profiles.pack(pady=5)

    def login(self):
        profile_name = self.profile_var.get()

        if not profile_name:
            messagebox.showerror("Error", "Please select a profile.")
            return
        if profile_name not in self.profiles:
            messagebox.showerror("Error", "Invalid profile selected.")
            return

        self.master_password = self.entry_master.get()

        if not self.master_password:
            messagebox.showerror("Error", "Master Password cannot be empty.")
            return

        
        if not self.profiles[profile_name]["key"]:
            self.key = self.derive_key(self.master_password)
            self.profiles[profile_name]["key"] = base64.urlsafe_b64encode(self.key).decode()
            self.save_profiles()
        else:
            try:
                key_bytes = base64.urlsafe_b64decode(self.profiles[profile_name]["key"])
                self.key = self.derive_key_from_bytes(self.master_password, key_bytes) 
            except Exception as e:
                messagebox.showerror("Error", f"Error loading key for profile: {e}")
                return

        self.current_profile = profile_name
        self.entry_master.delete(0, tk.END)
        self.login_frame.pack_forget()
        self.setup_main_screen()

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
        return kdf.derive(password) 

    def derive_key_from_bytes(self, password, salt_bytes):
        password = password.encode()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'salt_',
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password) 

    def generate_password(self, length=None):
        if length is None:
            length = self.default_password_length
        characters = string.ascii_letters + string.digits
        if self.include_symbols:
            characters += string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password

    def setup_main_screen(self):
       
        self.main_frame = tk.Frame(self.master, bg=self.bg_color)
        self.main_frame.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        
        self.generate_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.generate_frame, text="Generate")
        self.setup_generate_page()

        
        self.save_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.save_frame, text="Save")
        self.setup_save_page()

       
        self.view_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.view_frame, text="View")
        self.setup_view_page()

        
        self.settings_frame = tk.Frame(self.notebook, bg=self.bg_color)
        self.notebook.add(self.settings_frame, text="Settings")
        self.setup_settings_page()

    def setup_generate_page(self):
        length_label = tk.Label(self.generate_frame, text="Password Length:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        length_label.pack(pady=5)

        self.length_entry = tk.Entry(self.generate_frame, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.length_entry.insert(0, str(self.default_password_length))
        self.length_entry.pack(fill=tk.X, padx=20)

        self.symbol_var = tk.BooleanVar(value=self.include_symbols)
        symbol_check = tk.Checkbutton(self.generate_frame, text="Include Symbols", variable=self.symbol_var, bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10), activebackground=self.bg_color, selectcolor=self.highlight_color)
        symbol_check.pack(pady=5)

        generate_button = tk.Button(self.generate_frame, text="Generate", command=self.generate_and_display, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        generate_button.pack(pady=10)

        self.password_text = tk.Text(self.generate_frame, height=2, width=40, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.password_text.pack(pady=10)

    def setup_save_page(self):
        site_label = tk.Label(self.save_frame, text="Site Name:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        site_label.pack(pady=5)
        self.site_entry = tk.Entry(self.save_frame, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.site_entry.pack(fill=tk.X, padx=20)

        password_label = tk.Label(self.save_frame, text="Password:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        password_label.pack(pady=5)
        self.password_entry = tk.Entry(self.save_frame, show="*", bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.password_entry.pack(fill=tk.X, padx=20)

        save_button = tk.Button(self.save_frame, text="Save", command=self.save_password, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        save_button.pack(pady=10)

    def setup_view_page(self):
        self.view_listbox = tk.Listbox(self.view_frame, width=50, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color)
        self.view_listbox.pack(padx=20, pady=10)
        self.update_view_list() 

        show_button = tk.Button(self.view_frame, text="Show Password", command=self.show_password, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        show_button.pack(pady=10)

    def setup_settings_page(self):
       
        self.settings_frame.columnconfigure(0, weight=1)
        self.settings_frame.columnconfigure(1, weight=1)

        length_label = tk.Label(self.settings_frame, text="Default Password Length:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        length_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.default_length_var = tk.IntVar(value=self.default_password_length)
        length_entry = tk.Entry(self.settings_frame, textvariable=self.default_length_var, bg=self.entry_bg, fg=self.entry_fg, font=("Roboto", 10), bd=0, highlightthickness=1, highlightcolor=self.highlight_color, width=5)
        length_entry.grid(row=0, column=1, padx=10, pady=5, sticky="w")

        symbols_label = tk.Label(self.settings_frame, text="Include Symbols:", bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10))
        symbols_label.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.include_symbols_var = tk.BooleanVar(value=self.include_symbols)
        symbols_check = tk.Checkbutton(self.settings_frame, variable=self.include_symbols_var, bg=self.bg_color, fg=self.fg_color, font=("Roboto", 10), activebackground=self.bg_color, selectcolor=self.highlight_color)
        symbols_check.grid(row=1, column=1, padx=10, pady=5, sticky="w")

        apply_button = tk.Button(self.settings_frame, text="Apply", command=self.apply_settings, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        apply_button.grid(row=2, columnspan=2, pady=10)

    def apply_settings(self):
        try:
            self.default_password_length = int(self.default_length_var.get())
            if self.default_password_length <= 0:
                raise ValueError
            self.include_symbols = self.include_symbols_var.get()
            messagebox.showinfo("Success", "Settings applied successfully!")
        except ValueError:
            messagebox.showerror("Error", "Invalid password length.")

    def generate_and_display(self):
        try:
            length = int(self.length_entry.get())
            if length <= 0:
                raise ValueError("Length must be a positive integer.")
            self.include_symbols = self.symbol_var.get()
        except ValueError:
            messagebox.showerror("Error", "Invalid length. Please enter a positive integer.")
            return

        new_password = self.generate_password(length)
        self.password_text.delete(1.0, tk.END)
        self.password_text.insert(tk.END, new_password)

    def save_password(self):
        site_name = self.site_entry.get()
        password = self.password_entry.get()

        if not site_name or not password:
            messagebox.showerror("Error", "Site Name and Password cannot be empty.")
            return

        try:
            encrypted_password = self.encrypt(password)
            self.load_passwords()  
            self.passwords[site_name] = encrypted_password
            self.save_passwords()
            messagebox.showinfo("Success", "Password saved successfully!")
            self.site_entry.delete(0, tk.END)
            self.password_entry.delete(0, tk.END)
            self.update_view_list() 
        except Exception as e:
            messagebox.showerror("Error", f"Error saving password: {e}")

    def show_password(self):
        try:
            selected_site = self.view_listbox.get(self.view_listbox.curselection())
            encrypted_password = self.passwords.get(selected_site)
            if not encrypted_password:
                messagebox.showerror("Error", "Password not found for selected site.")
                return
            decrypted_password = self.decrypt(encrypted_password)
            messagebox.showinfo("Password", f"Password for {selected_site}: {decrypted_password}")
        except tk.TclError:
            messagebox.showerror("Error", "No site selected.")
        except Exception as e:
            messagebox.showerror("Error", f"Error decrypting password: {e}")

    def update_view_list(self):
        self.view_listbox.delete(0, tk.END)
        try:
            self.load_passwords()
        except FileNotFoundError:
            self.passwords = {}
        except Exception as e:
            messagebox.showerror("Error", f"Error loading passwords: {e}")
            self.passwords = {}

        for site in self.passwords:
            self.view_listbox.insert(tk.END, site)

    def encrypt(self, data):
        f = Fernet(self.key)
        return f.encrypt(data.encode()).decode()

    def decrypt(self, data):
        f = Fernet(self.key)
        return f.decrypt(data.encode()).decode()

    def load_passwords(self):
        try:
            with open(self.get_password_file(), "r") as f:
                data = json.load(f)
                self.passwords = {str(k): v for k, v in data.items()}  
        except FileNotFoundError:
            self.passwords = {}
        except json.JSONDecodeError:
            self.passwords = {}
        except Exception as e:
            messagebox.showerror("Error", f"Error loading passwords: {e}")
            self.passwords = {}


    def save_passwords(self):
        try:
            with open(self.get_password_file(), "w") as f:
                json.dump(self.passwords, f)
        except Exception as e:
            messagebox.showerror("Error", f"Error saving passwords: {e}")

    def get_password_file(self):
        """Возвращает путь к файлу с паролями для текущего профиля."""
        if self.current_profile and self.profiles.get(self.current_profile):
            return self.profiles[self.current_profile]["password_file"]
        return "default_passwords.json" 

    
    def load_profiles(self):
        try:
            with open(self.profiles_file, "r") as f:
                self.profiles = json.load(f)
        except FileNotFoundError:
            self.profiles = {}
        except json.JSONDecodeError:
            self.profiles = {}
        except Exception as e:
            messagebox.showerror("Error", f"Error loading profiles: {e}")
            self.profiles = {}

    def save_profiles(self):
        try:
            with open(self.profiles_file, "w") as f:
                json.dump(self.profiles, f)
        except Exception as e:
            messagebox.showerror("Error", f"Error saving profiles: {e}")

    def open_profile_management(self):
        
        profile_window = tk.Toplevel(self.master)
        profile_window.title("Manage Profiles")
        profile_window.geometry("300x250") 
        profile_window.configure(bg=self.bg_color)

        
        def create_profile():
            profile_name = simpledialog.askstring("Create Profile", "Enter profile name:")
            if profile_name:
                if profile_name in self.profiles:
                    messagebox.showerror("Error", "Profile with this name already exists.")
                    return
                self.profiles[profile_name] = {
                    "key": None,
                    "password_file": f"{profile_name}_passwords.json"
                }
                self.save_profiles()
                self.profile_dropdown["values"] = list(self.profiles.keys())  
                messagebox.showinfo("Success", f"Profile '{profile_name}' created.")

        def delete_profile():
            profile_name = simpledialog.askstring("Delete Profile", "Enter profile name to delete:")
            if profile_name and profile_name in self.profiles:
                if profile_name == self.current_profile:
                    messagebox.showerror("Error", "Cannot delete currently active profile.")
                    return
                del self.profiles[profile_name]
                self.save_profiles()
                self.profile_dropdown["values"] = list(self.profiles.keys())  
                messagebox.showinfo("Success", f"Profile '{profile_name}' deleted.")
            elif profile_name:
                messagebox.showerror("Error", "Profile not found.")

        def rename_profile():
            profile_name = simpledialog.askstring("Rename Profile", "Enter profile name to rename:")
            if profile_name and profile_name in self.profiles:
                new_name = simpledialog.askstring("Rename Profile", "Enter new profile name:")
                if new_name and new_name != profile_name and new_name not in self.profiles:
                    self.profiles[new_name] = self.profiles.pop(profile_name)
                    self.profiles[new_name]["password_file"] = f"{new_name}_passwords.json" 
                    self.save_profiles()
                    self.profile_dropdown["values"] = list(self.profiles.keys())  
                    messagebox.showinfo("Success", f"Profile renamed to '{new_name}'.")
                elif new_name and new_name in self.profiles:
                    messagebox.showerror("Error", "Profile with this name already exists.")
                elif new_name:
                    messagebox.showerror("Error", "Invalid name.")
            elif profile_name:
                messagebox.showerror("Error", "Profile not found.")

        
        create_button = tk.Button(profile_window, text="Create Profile", command=create_profile, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        create_button.pack(pady=5)

        delete_button = tk.Button(profile_window, text="Delete Profile", command=delete_profile, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        delete_button.pack(pady=5)

        rename_button = tk.Button(profile_window, text="Rename Profile", command=rename_profile, bg=self.button_bg, fg=self.button_fg, font=("Roboto", 10), bd=0, padx=10, pady=5, relief=tk.FLAT)
        rename_button.pack(pady=5)

    def switch_profile(self, profile_name):
        
        if profile_name in self.profiles:
            self.current_profile = profile_name
            
            
            self.load_passwords()
            
            self.profile_var.set(profile_name) 
            self.login() 

root = tk.Tk()
my_gui = PasswordManager(root)
root.mainloop()
