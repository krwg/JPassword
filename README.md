# Password Manager in Python with GUI (JPassword)

## Overview

Password Manager is a secure and user-friendly application designed for managing your passwords. It allows you to generate strong, random passwords, securely store them in encrypted files, and easily access them whenever you need them. With profile support, you can manage passwords for different contexts separately.

## Features

*   **Password Generation:**
    *   Generate strong, random passwords with customizable length.
    *   Option to include or exclude symbols in generated passwords.
*   **Password Storage:**
    *   Securely store passwords associated with website/account names.
    *   Encrypt passwords using robust encryption algorithms (Fernet).
    *   Store passwords in separate files for each profile.
*   **Password Management with Profiles:**
    *   Create, rename, and delete profiles to manage different sets of passwords.
    *   Switch between profiles easily.
*   **Password Viewing:**
    *   View stored passwords securely after entering the master password.
*   **Settings:**
    *   Configure the default password length.
    *   Enable or disable the inclusion of symbols in generated passwords.
*   **Security:**
    *   Encrypt passwords using Fernet encryption.
    *   Protect encryption keys using a master password.
    *   Use PBKDF2 for key derivation from the master password.
*   **GUI (Graphical User Interface):**
    *   Intuitive and easy-to-use interface built with Tkinter.
    *   Modern design principles inspired by Material Design (Android).

## How It Works

1.  **Profile Selection/Creation:** On startup, the application prompts you to select an existing profile or create a new one.
2.  **Master Password Entry:** Enter your master password. This password unlocks the encryption key for the selected profile.
3.  **Password Generation:** Generate random passwords with customizable length and symbol inclusion.
4.  **Password Storage:** Save passwords securely by associating them with website/account names. The passwords are encrypted using the key derived from the master password and stored in a profile-specific file.
5.  **Password Viewing:** View your saved passwords securely within the application.

## Requirements

*   Python 3.x
*   `cryptography` library: `pip install cryptography`

## Installation

1.  Install the required libraries:
    ```bash
    pip install cryptography
    ```
2.  Run the application:
    ```bash
    python password_manager.py (or your file name)
    ```

## Usage

1.  **Start the Application:** Launch the Password Manager application.
2.  **Select or Create a Profile:** Choose an existing profile from the dropdown menu or create a new one using the "Manage Profiles" button.
3.  **Enter Master Password:** Enter your master password and click "Login."
4.  **Generate Passwords:** Use the "Generate" tab to generate random passwords. Customize the length and symbol inclusion as desired.
5.  **Save Passwords:** Go to the "Save" tab to save passwords. Enter the website/account name and the password you want to store.
6.  **View Passwords:** Access the "View" tab to see your saved passwords.
7.  **Configure Settings:** Use the "Settings" tab to adjust the default password length and symbol inclusion.
8.  **Manage Profiles:** Click the "Manage Profiles" button to create, rename, or delete profiles.

## Security

*   **Master Password:**
    *   Choose a strong and unique master password.
    *   Remember your master password. Loss of the master password means loss of access to your stored passwords.
*   **Profiles:** Use profiles to separate and manage passwords for different areas of your life.
*   **Salt:** The salt used in this application for PBKDF2 is currently hardcoded for demonstration purposes. In a production environment, it's crucial to use randomly generated salts stored securely for each profile.
*   **Library Updates:** Keep the `cryptography` library updated to benefit from the latest security patches and improvements.
*   **Backup:** Regularly back up your profile files (`*_passwords.json` and `profiles.json`) to prevent data loss.
*   **Never Share:** Do not share your `passwords.json`, `profiles.json`, or master password with anyone.

## Future Enhancements (Roadmap)

*   [ ] Implement secure, randomly generated, profile-specific salts for PBKDF2.
*   [ ] Add password strength indicators.
*   [ ] Enhance the user interface with icons and more customization options.
*   [ ] Implement password export and import functionality.
*   [ ] Implement auto-fill functionality for web browsers.
*   [ ] Consider adding multi-factor authentication options.

