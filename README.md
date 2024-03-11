# FolderCrypt

FolderCrypt is a simple, yet powerful tool designed to encrypt and decrypt folders on your computer with ease. Utilizing the robust AES encryption standard through the pyAesCrypt library and PyQt5 for a user-friendly graphical interface, FolderCrypt offers an accessible way to secure your data.

## Features

- **Easy-to-use GUI**: Drag and drop folders to encrypt or decrypt them.
- **AES Encryption**: Uses the AES standard to ensure secure encryption and decryption of your data.
- **Progress Indication**: Real-time progress feedback during encryption and decryption processes.
- **Cross-platform Compatibility**: Works on Windows, macOS, and Linux.

## Installation

Before running FolderCrypt, ensure you have Python 3 and pip installed on your system. Then, install the necessary dependencies by running:

```bash
pip install PyQt5 pyAesCrypt
```
Running FolderCrypt
To start the FolderCrypt application, navigate to the folder containing foldercrypt.py and run:

```bash
python foldercrypt.py
```

Usage
To Encrypt: Drag and drop a folder onto the app window or click the "Encrypt" button to select a folder. Enter a password when prompted.

To Decrypt: Drag and drop an .aes encrypted file onto the app window or click the "Decrypt" button to select a file. Enter the correct password when prompted.

Contributing
Contributions are welcome! Feel free to fork the repository and submit pull requests. If you encounter any issues or have suggestions for improvements, please open an issue.

License
FolderCrypt is released under MIT License.

Acknowledgments
pyAesCrypt: For providing the encryption functionality.
PyQt5: For enabling the creation of the graphical user interface.
Thank you for using or contributing to FolderCrypt!
