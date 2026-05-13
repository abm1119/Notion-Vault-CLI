# Notion Vault CLI

Notion Vault CLI is a local, encrypted password vault you talk to in plain English.

It stores passwords, usernames, and small private notes on your machine only. There is no cloud sync, no browser extension, and no account setup. You open the vault with one master password, then ask for what you need with commands like:

```text
save github in personal as ali
what's my github password in personal
list all
remember my uni email is ali@student.edu
```

## Features

- Local encrypted storage using `cryptography`
- Natural-language style CLI commands
- Folder-based organization such as `Personal`, `Education`, `Business`, or custom folders
- Multi-word folder and service names such as `borlo labs` or `notion vault`
- Password generation with clipboard auto-clear
- Search, move, delete, and quick listing commands
- Small fact memory for things like emails, IDs, or Wi-Fi labels
- Rich terminal panels and tables for a more interactive CLI experience

## Requirements

- Python `3.14+`
- `uv`

## Install

```powershell
uv sync
```

## Run

```powershell
uv run notion-vault
```

This project also installs:

```powershell
uv run notion-vault-cli
```

## First Run

On first launch, Notion Vault CLI will ask you to create a master password.

It stores local files in your home directory:

- `~/.notion_vault.db` for new vaults
- `~/.notion_vault.salt` for the key-derivation salt
- `~/.notion_vault.history` for prompt history

It also recognizes the older legacy files:

- `~/.pma_vault.db`
- `~/.pma_salt`
- `~/.pma_history`

If those older files already exist, the CLI will continue using them.

## Command Guide

### Save a login

```text
save github in personal as ali
save notion vault in borlo labs as ali.work
add figma to client work
```

If you leave the password blank when prompted, the CLI generates one for you.

### Retrieve a password

```text
what's my github password in personal
show github
get notion vault from borlo labs
```

### List saved entries

```text
list all
list personal
list borlo labs
show passwords
```

### Search

```text
find github
search for aws
```

### Move between folders

```text
move aws from business to client work
```

### Delete an entry

```text
delete github from personal
```

### Generate a password

```text
generate password
generate password 24
```

### Copy a password to clipboard

```text
copy github
copy my github password from personal
```

If clipboard support is available, the copied password is cleared after 15 seconds.

### Store and recall facts

```text
remember my uni email is ali@student.edu
what is my uni email
recall my uni email
```

### Built-in utility views

```text
help
folders
summary
quit
```

## Folder Behavior

Notion Vault starts with:

- `Personal`
- `Education`
- `Business`

You can create a new folder simply by saving something into it:

```text
save figma in borlo labs as ali
```

That creates `Borlo Labs` automatically if it does not already exist.

## Security Notes

- Passwords are encrypted before being stored in SQLite
- The salt is stored separately in your home directory
- Everything runs locally on your machine
- Clipboard clearing is best-effort and depends on system clipboard support
- If you lose your master password, there is no recovery flow in this version

## Project Layout

- [notion_vault_cli.py](./notion_vault_cli.py) contains the full CLI
- [pyproject.toml](./pyproject.toml) defines packaging and command entry points
- [uv.lock](./uv.lock) locks dependencies
- [Password-agent-design.html](./Password-agent-design.html) is a design/manual mockup

## Development

Install dependencies:

```powershell
uv sync
```

Run the module directly:

```powershell
uv run python notion_vault_cli.py
```

Check syntax:

```powershell
uv run python -m py_compile notion_vault_cli.py
```

## Current Scope

This is a single-file CLI application. It is intentionally simple and currently focuses on:

- local vault storage
- natural-language commands
- terminal interaction

It does not currently include:

- cloud sync
- browser autofill
- multi-user accounts
- export/import workflows
- a GUI
