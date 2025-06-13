# Password Manager in Python with GUI (JPassword)

## Overview

Password Manager is a simple yet secure application for storing and managing your passwords. The application allows you to generate strong passwords, save them in an encrypted format, and access them when needed.

## Features

*   **Password Generation:**
    *   Generates random passwords of a specified length.
    *   Customizable password length.
*   **Password Saving:**
    *   Saves passwords with the associated website/account name.
    *   Password encryption for security.
*   **Password Viewing:**
    *   Secure access to saved passwords.
    *   Displays the website/account name and the corresponding password.
    *   Copy password to clipboard (future enhancement).
*   **Security:**
    *   Password encryption using a strong algorithm (Fernet).
    *   Master password protection for the encryption key.
    *   Uses PBKDF2 to derive the encryption key from the master password.
*   **GUI (Graphical User Interface):**
    *   Simple and intuitive interface developed using Tkinter.
    *   Modern design based on Material Design (Android) principles.

## How It Works

1.  **Launch:** Upon launching the application, the user is prompted to enter a master password. This password is used to derive the encryption key.
2.  **Password Generation:** The user can generate a random password of a specified length.
3.  **Password Saving:** After generating or entering a password, the user can save it by specifying the website/account name. The password is encrypted using the key derived from the master password and saved to the `passwords.json` file.
4.  **Password Viewing:** The user can view saved passwords by selecting the website/account name. Upon selection, the encrypted password is decrypted using the key derived from the master password and displayed to the user.

## Requirements

*   Python 3.x
*   `cryptography` library: `pip install cryptography`

## Installation

1.  Install the necessary libraries:
    ```bash
    pip install cryptography
    ```
2.  Run the application:
    ```bash
    python password_manager.py (or your file name)
    ```

## Usage

1.  **Launch:** Run the application.
2.  **Enter Master Password:** Enter your master password and click "Login."
3.  **Generate Password:** Click the "Generate Password" button, enter the desired password length, and click "Generate." Copy the generated password.
4.  **Save Password:** Click the "Save Password" button, enter the website/account name and password, then click "Save."
5.  **View Passwords:** Click the "View Passwords" button to view your saved passwords. Select a website/account name from the list to see the corresponding password.

## Security

*   **Master Password:** Keep your master password secure. Losing your master password will result in the loss of access to all your passwords.
*   **Salt:** In the current implementation, the salt for PBKDF2 is hardcoded. In a real-world application, the salt should be randomly generated and stored separately from the master password. (Will be updated soon)
*   **Regularly update libraries.** Make sure you have the latest versions of `cryptography` to have security patches.
*   **Backup:** Consider backing up the `passwords.json` file.
*   **Do not share `passwords.json` or your master password.**

## Future Enhancements (Roadmap)

*   [ ] Add a copy-to-clipboard function.
*   [ ] Implement secure salt generation and storage.
*   [ ] Add functionality to edit existing passwords.
*   [ ] Implement a search function for saved passwords.
*   [ ] Improve the user interface (more responsive design, icons).
*   [ ] Add an import/export option for passwords.
*   [ ] Support for multiple user profiles.
*   [ ] Add warnings for weak passwords.
*   [ ] Integrate with a browser for autofill (requires browser extensions).

## License
No
