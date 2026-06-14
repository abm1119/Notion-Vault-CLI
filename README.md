# 🔐 Notion Vault CLI

[![PyPI version](https://img.shields.io/pypi/v/notion-vault-cli.svg)](https://pypi.org/project/notion-vault-cli/)
[![Python versions](https://img.shields.io/pypi/pyversions/notion-vault-cli.svg)](https://pypi.org/project/notion-vault-cli/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Notion Vault CLI** is a private, encrypted password vault that you talk to in plain English. 

It stores passwords, usernames, and small private notes on your machine only. There is no cloud sync, no browser extension, and no account setup. You open the vault with one master password, then ask for what you need using natural language.

---

## ✨ Key Features

- 🧠 **Natural Language Interface**: Save and retrieve data using intuitive sentences.
- 🛡️ **Zero-Knowledge Encryption**: Local storage using `cryptography` (AES-256).
- 📁 **Dynamic Folders**: Organize entries into `Personal`, `Work`, or custom folders on the fly.
- 📋 **Secure Clipboard**: Automatic clipboard clearing after 15 seconds.
- ⚡ **Rich UI**: Interactive tables, panels, and progress indicators.
- 💾 **Small Facts**: Remember Wi-Fi codes, IDs, or emails without full login entries.
- 🏠 **100% Local**: Your data never leaves your machine.

---

## 🚀 Installation

### Using pip (Recommended)
Install directly from [PyPI](https://pypi.org/project/notion-vault-cli/):
```powershell
pip install notion-vault-cli
```

### For Developers
If you want to contribute or run from source:
1. Clone the repository:
   ```powershell
   git clone https://github.com/abm1119/Notion-Vault-CLI.git
   cd Notion-Vault-CLI
   ```
2. Install dependencies using `uv`:
   ```powershell
   uv sync
   ```

---

## 🛠️ Getting Started

### 1. Launch the Vault
```powershell
notion-vault
```
*(On first run, you will be prompted to create your Master Password. **Do not lose it!**)*

### 2. Save Your First Login
```text
save github in Personal as abm1119
```
The vault will prompt you for the password. Leave it blank to **auto-generate** a secure one.

### 3. Retrieve it
```text
what's my github password in Personal
```

---

## 📖 Command Guide

| Action | Example Command |
| :--- | :--- |
| **Save** | `save netflix in entertainment as me@email.com` |
| **Get Password** | `show github` or `get aws from work` |
| **List Entries** | `list all`, `list personal`, `show passwords` |
| **Search** | `find bank`, `search for figma` |
| **Clipboard** | `copy github`, `copy my personal aws password` |
| **Facts** | `remember my uni email is me@edu.com`, `what is my uni email?` |
| **Organize** | `move aws from business to cloud` |
| **Delete** | `delete github from personal` |
| **Utilities** | `folders`, `summary`, `generate password 24`, `help` |

---

## 🔒 Security Architecture

- **Encryption**: Data is encrypted using `Fernet` (symmetric encryption) which uses AES-256 in CBC mode with HMAC-SHA256.
- **Key Derivation**: Your Master Password is never stored. We use `PBKDF2HMAC` with a unique local salt to derive the encryption key.
- **Local Files**:
  - `~/.notion_vault.db`: The encrypted SQLite database.
  - `~/.notion_vault.salt`: Your unique derivation salt.
  - `~/.notion_vault.history`: Local command history for easy recall.

---

## 🤝 Contributing

Contributions are welcome! Whether it's a bug fix, a new feature, or better natural language parsing:

1. Fork the Project.
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`).
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`).
4. Push to the Branch (`git checkout push origin feature/AmazingFeature`).
5. Open a Pull Request.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

---

**Developed with ❤️ by [abm1119](https://github.com/abm1119)**
