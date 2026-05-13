#!/usr/bin/env python3
"""
Notion Vault CLI
Natural-language password vault with local encrypted storage.
"""

import base64
import difflib
import getpass
import os
import re
import secrets
import sqlite3
import string
import sys
import threading
import time
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text

    console = Console()
except Exception:
    print("pip install rich")
    sys.exit(1)

try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.history import FileHistory

    PTK = True
except Exception:
    PTK = False

try:
    import pyperclip

    HAS_CLIP = True
except Exception:
    HAS_CLIP = False

APP_NAME = "Notion Vault"
APP_TAGLINE = "Local, encrypted, natural-language password storage"

LEGACY_VAULT = Path.home() / ".pma_vault.db"
LEGACY_SALT = Path.home() / ".pma_salt"
LEGACY_HIST = Path.home() / ".pma_history"

DEFAULT_VAULT = Path.home() / ".notion_vault.db"
DEFAULT_SALT = Path.home() / ".notion_vault.salt"
DEFAULT_HIST = Path.home() / ".notion_vault.history"


def choose_path(default_path: Path, legacy_path: Path) -> Path:
    if default_path.exists():
        return default_path
    if legacy_path.exists():
        return legacy_path
    return default_path


VAULT = choose_path(DEFAULT_VAULT, LEGACY_VAULT)
SALT = choose_path(DEFAULT_SALT, LEGACY_SALT)
HIST = choose_path(DEFAULT_HIST, LEGACY_HIST)

FOLDER_CHOICES = ("Personal", "Education", "Business")
COMMAND_EXAMPLES = [
    "save github in personal as ali",
    "save notion vault in borlo labs as ali.work",
    "what's my github password in personal",
    "list all",
    "move aws from business to client work",
    "remember my uni email is ali@student.edu",
]


def format_name(value: str) -> str:
    return " ".join(word.capitalize() for word in value.strip().split())


def safe_chmod(path: Path, mode: int):
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def derive_key(master: str) -> bytes:
    if not SALT.exists():
        SALT.write_bytes(os.urandom(16))
        safe_chmod(SALT, 0o600)
    salt = SALT.read_bytes()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return base64.urlsafe_b64encode(kdf.derive(master.encode()))


def get_conn():
    conn = sqlite3.connect(VAULT)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS categories(
            id INTEGER PRIMARY KEY,
            name TEXT UNIQUE COLLATE NOCASE,
            created_at REAL
        );
        CREATE TABLE IF NOT EXISTS entries(
            id INTEGER PRIMARY KEY,
            category_id INTEGER,
            service TEXT COLLATE NOCASE,
            username TEXT,
            password BLOB,
            notes TEXT,
            created_at REAL,
            updated_at REAL,
            accessed_at REAL,
            UNIQUE(category_id, service),
            FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS facts(
            key TEXT PRIMARY KEY COLLATE NOCASE,
            value TEXT,
            updated_at REAL
        );
        CREATE TABLE IF NOT EXISTS audit(
            ts REAL,
            action TEXT,
            detail TEXT
        );
        CREATE TABLE IF NOT EXISTS meta(
            key TEXT PRIMARY KEY COLLATE NOCASE,
            value BLOB
        );
        """
    )
    for folder in FOLDER_CHOICES:
        conn.execute(
            "INSERT OR IGNORE INTO categories(name, created_at) VALUES(?, ?)",
            (folder, time.time()),
        )
    conn.commit()
    conn.close()
    safe_chmod(VAULT, 0o600)


def encrypt_value(fernet: Fernet, text: str) -> bytes:
    return fernet.encrypt(text.encode())


def decrypt_value(fernet: Fernet, blob: bytes) -> str:
    return fernet.decrypt(blob).decode()


def generate_password(length: int = 16) -> str:
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256 characters.")
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*-_"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def copy_with_timeout(text: str, seconds: int = 15) -> bool:
    if not HAS_CLIP:
        return False
    pyperclip.copy(text)

    def clear_clipboard():
        time.sleep(seconds)
        if pyperclip.paste() == text:
            pyperclip.copy("")

    threading.Thread(target=clear_clipboard, daemon=True).start()
    return True


class NotionVaultCLI:
    def __init__(self, fernet: Fernet):
        self.fernet = fernet
        self.conn = get_conn()
        self.last_folder = None
        self.last_service = None

    def log(self, action: str, detail: str = ""):
        self.conn.execute("INSERT INTO audit VALUES (?, ?, ?)", (time.time(), action, detail))

    def categories(self):
        return [row[0] for row in self.conn.execute("SELECT name FROM categories ORDER BY name")]

    def services(self):
        return [row[0] for row in self.conn.execute("SELECT DISTINCT service FROM entries ORDER BY service")]

    def counts(self):
        row = self.conn.execute(
            """
            SELECT
                (SELECT COUNT(*) FROM categories) AS folders,
                (SELECT COUNT(*) FROM entries) AS entries,
                (SELECT COUNT(*) FROM facts) AS facts
            """
        ).fetchone()
        return row["folders"], row["entries"], row["facts"]

    def close(self):
        self.conn.close()

    def ensure_master_password(self):
        token = "notion-vault-check"
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS meta(
                key TEXT PRIMARY KEY COLLATE NOCASE,
                value BLOB
            )
            """
        )
        row = self.conn.execute("SELECT value FROM meta WHERE key = 'vault-check'").fetchone()
        if row:
            try:
                return decrypt_value(self.fernet, row["value"]) == token
            except InvalidToken:
                return False

        sample = self.conn.execute("SELECT password FROM entries LIMIT 1").fetchone()
        if sample:
            try:
                decrypt_value(self.fernet, sample["password"])
            except InvalidToken:
                return False

        self.conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)",
            ("vault-check", encrypt_value(self.fernet, token)),
        )
        self.conn.commit()
        return True

    def fuzzy(self, name: str, options):
        if not options:
            return name
        exact = {option.lower(): option for option in options}
        if name.lower() in exact:
            return exact[name.lower()]
        lowered = [option.lower() for option in options]
        match = difflib.get_close_matches(name.lower(), lowered, n=1, cutoff=0.7)
        if not match:
            return name
        index = lowered.index(match[0])
        return options[index]

    def resolve_folder(self, folder: str) -> str:
        folder = " ".join(folder.strip().split())
        return format_name(self.fuzzy(folder, self.categories()))

    def resolve_service(self, service: str) -> str:
        service = " ".join(service.strip().split()).lower()
        return self.fuzzy(service, self.services()).lower()

    def save_entry(self, folder: str, service: str, username: str, password: str = None):
        folder = format_name(" ".join(folder.strip().split()))
        service = " ".join(service.strip().split()).lower()
        username = username.strip()
        if not password:
            password = generate_password()
        category = self.conn.execute("SELECT id FROM categories WHERE name = ?", (folder,)).fetchone()
        if not category:
            self.conn.execute(
                "INSERT INTO categories(name, created_at) VALUES(?, ?)",
                (folder, time.time()),
            )
            category = self.conn.execute("SELECT id FROM categories WHERE name = ?", (folder,)).fetchone()
        self.conn.execute(
            """
            INSERT INTO entries(category_id, service, username, password, created_at, updated_at)
            VALUES(?, ?, ?, ?, ?, ?)
            ON CONFLICT(category_id, service) DO UPDATE SET
                username = excluded.username,
                password = excluded.password,
                updated_at = excluded.updated_at
            """,
            (
                category[0],
                service,
                username,
                encrypt_value(self.fernet, password),
                time.time(),
                time.time(),
            ),
        )
        self.log("ADD", f"{folder}/{service}")
        self.conn.commit()
        self.last_folder = folder
        self.last_service = service
        return folder, service, password

    def get_entry(self, folder: str, service: str):
        folder = self.resolve_folder(folder)
        service = self.resolve_service(service)
        row = self.conn.execute(
            """
            SELECT e.username, e.password
            FROM entries e
            JOIN categories c ON e.category_id = c.id
            WHERE c.name = ? AND e.service = ?
            """,
            (folder, service),
        ).fetchone()
        if not row:
            return None, None, folder, service
        self.last_folder = folder
        self.last_service = service
        self.log("GET", f"{folder}/{service}")
        self.conn.commit()
        return row["username"], decrypt_value(self.fernet, row["password"]), folder, service

    def list_folder(self, folder: str = None):
        if folder:
            folder = self.resolve_folder(folder)
            rows = self.conn.execute(
                """
                SELECT service, username
                FROM entries e
                JOIN categories c ON e.category_id = c.id
                WHERE c.name = ?
                ORDER BY service
                """,
                (folder,),
            ).fetchall()
            title = f"{folder} vault"
            table = Table(title=title, box=box.ROUNDED, header_style="bold cyan")
            table.add_column("Service", style="white")
            table.add_column("Username", style="green")
            for row in rows:
                table.add_row(row["service"], row["username"] or "-")
            return table, rows

        rows = self.conn.execute(
            """
            SELECT c.name, e.service, e.username
            FROM entries e
            JOIN categories c ON e.category_id = c.id
            ORDER BY c.name, e.service
            """
        ).fetchall()
        table = Table(title="All saved logins", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Folder", style="magenta")
        table.add_column("Service", style="white")
        table.add_column("Username", style="green")
        for row in rows:
            table.add_row(row["name"], row["service"], row["username"] or "-")
        return table, rows

    def search_entries(self, query: str):
        rows = self.conn.execute(
            """
            SELECT c.name, e.service, e.username
            FROM entries e
            JOIN categories c ON e.category_id = c.id
            WHERE e.service LIKE ? OR e.username LIKE ?
            ORDER BY c.name, e.service
            """,
            (f"%{query}%", f"%{query}%"),
        ).fetchall()
        return rows

    def move_entry(self, service: str, source: str, destination: str):
        service = self.resolve_service(service)
        source = self.resolve_folder(source)
        destination = self.resolve_folder(destination)
        destination_row = self.conn.execute("SELECT id FROM categories WHERE name = ?", (destination,)).fetchone()
        if not destination_row:
            self.conn.execute(
                "INSERT INTO categories(name, created_at) VALUES(?, ?)",
                (destination, time.time()),
            )
            destination_row = self.conn.execute(
                "SELECT id FROM categories WHERE name = ?",
                (destination,),
            ).fetchone()
        result = self.conn.execute(
            """
            UPDATE entries
            SET category_id = ?, updated_at = ?
            WHERE service = ?
              AND category_id = (SELECT id FROM categories WHERE name = ?)
            """,
            (destination_row[0], time.time(), service, source),
        )
        self.conn.commit()
        return result.rowcount, service, source, destination

    def delete_entry(self, folder: str, service: str):
        folder = self.resolve_folder(folder)
        service = self.resolve_service(service)
        result = self.conn.execute(
            """
            DELETE FROM entries
            WHERE service = ?
              AND category_id = (SELECT id FROM categories WHERE name = ?)
            """,
            (service, folder),
        )
        self.conn.commit()
        return result.rowcount, folder, service

    def remember_fact(self, key: str, value: str):
        self.conn.execute(
            """
            INSERT INTO facts VALUES(?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                value = excluded.value,
                updated_at = excluded.updated_at
            """,
            (key.lower(), value, time.time()),
        )
        self.conn.commit()

    def recall_fact(self, key: str):
        row = self.conn.execute("SELECT value FROM facts WHERE key = ?", (key.lower(),)).fetchone()
        return row["value"] if row else None

    def parse(self, text: str):
        normalized = " ".join(text.strip().split())
        lower = normalized.lower()

        if lower in {"help", "commands", "?"}:
            return "help", []
        if lower in {"folders", "categories"}:
            return "folders", []
        if lower in {"summary", "stats", "dashboard"}:
            return "summary", []

        match = re.match(r"remember (?:that )?(.+?) is (.+)$", normalized, re.IGNORECASE)
        if match:
            return "remember", [match.group(1).strip(), match.group(2).strip()]

        match = re.match(r"(?:what is|recall|what's) (?:my )?(.+)$", normalized, re.IGNORECASE)
        if match and "password" not in lower:
            return "recall", [match.group(1).strip()]

        match = re.match(
            r"(?:save|store|add) (?:my )?(.+?)(?: password)? (?:in|to|for|under) (.+?)(?: as (.+))?$",
            normalized,
            re.IGNORECASE,
        )
        if match:
            return "add", [match.group(2).strip(), match.group(1).strip(), (match.group(3) or "").strip()]

        match = re.match(r"add (.+?) to (.+)$", normalized, re.IGNORECASE)
        if match:
            return "add", [match.group(2).strip(), match.group(1).strip(), ""]

        match = re.match(
            r"(?:get|show|what is|what's) (?:my )?(.+?) password (?:in|from|for) (.+)$",
            normalized,
            re.IGNORECASE,
        )
        if match:
            return "get", [match.group(2).strip(), match.group(1).strip()]

        if re.search(r"what passwords do i have|show passwords", lower):
            return "list", []

        match = re.match(r"(?:get|show) (.+?)(?: from (.+))?$", normalized, re.IGNORECASE)
        if match:
            folder = (match.group(2) or self.last_folder or "Personal").strip()
            return "get", [folder, match.group(1).strip()]

        match = re.match(r"(?:list)(?: (.+))?$", normalized, re.IGNORECASE)
        if match:
            folder = (match.group(1) or "").strip()
            if not folder or folder.lower() == "all":
                return "list", []
            if folder.lower() == "passwords":
                return "list", []
            return "list", [folder]

        match = re.match(r"(?:find|search for|search) (.+)$", normalized, re.IGNORECASE)
        if match:
            return "find", [match.group(1).strip()]

        match = re.match(r"move (.+?) from (.+?) to (.+)$", normalized, re.IGNORECASE)
        if match:
            return "move", [match.group(1).strip(), match.group(2).strip(), match.group(3).strip()]

        match = re.match(r"delete (.+?)(?: from| in) (.+)$", normalized, re.IGNORECASE)
        if match:
            return "delete", [match.group(2).strip(), match.group(1).strip()]

        match = re.match(r"(?:generate|create)(?: a)? password(?: (\d+))?$", lower, re.IGNORECASE)
        if match:
            return "generate", [match.group(1) or "16"]

        match = re.match(r"copy (?:my )?(.+?)(?: password)?(?: from (.+))?$", normalized, re.IGNORECASE)
        if match:
            folder = (match.group(2) or self.last_folder or "Personal").strip()
            return "copy", [folder, match.group(1).strip()]

        return "unknown", []

    def render_summary(self):
        folders, entries, facts = self.counts()
        table = Table(title="Vault overview", box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("Metric")
        table.add_column("Value", justify="right")
        table.add_row("Folders", str(folders))
        table.add_row("Passwords", str(entries))
        table.add_row("Facts", str(facts))
        return table

    def render_folders(self):
        table = Table(title="Folders", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Name", style="magenta")
        for folder in self.categories():
            table.add_row(folder)
        return table

    def render_help(self):
        table = Table(title="Command guide", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("Action", style="magenta")
        table.add_column("Example", style="white")
        table.add_row("Save a login", "save github in personal as ali")
        table.add_row("Create a new folder", "save figma in borlo labs as ali")
        table.add_row("Fetch a password", "what's my github password in personal")
        table.add_row("Quick fetch", "show github")
        table.add_row("List everything", "list all")
        table.add_row("List one folder", "list borlo labs")
        table.add_row("Move a login", "move aws from business to client work")
        table.add_row("Remember a fact", "remember wifi code is delta-42")
        table.add_row("Generate a password", "generate password 24")
        table.add_row("Show dashboard", "summary")
        return table

    def handle(self, text: str):
        intent, args = self.parse(text)

        if intent == "help":
            console.print(self.render_help())
            return

        if intent == "folders":
            console.print(self.render_folders())
            return

        if intent == "summary":
            console.print(self.render_summary())
            return

        if intent == "add":
            folder, service, username = args
            if not username:
                username = console.input(f"[cyan]Username for {service} in {folder}:[/cyan] ").strip()
            password = getpass.getpass("Password (leave blank to generate): ")
            if not password:
                password = generate_password()
            folder, service, saved_password = self.save_entry(folder, service, username, password)
            body = (
                f"[bold]{service}[/bold] saved in [bold magenta]{folder}[/bold magenta]\n"
                f"Username: [green]{username}[/green]\n"
                f"Password: [yellow]{saved_password}[/yellow]"
            )
            console.print(Panel(body, title="Saved", border_style="green"))
            if copy_with_timeout(saved_password):
                console.print("[dim]Password copied to clipboard for 15 seconds.[/dim]")
            return

        if intent == "get":
            username, password, folder, service = self.get_entry(args[0], args[1])
            if not username:
                console.print(Panel("Nothing matched that request. Try `list all` or `find github`.", title="Not found", border_style="red"))
                return
            body = (
                f"[bold magenta]{folder}[/bold magenta] / [bold]{service}[/bold]\n"
                f"Username: [green]{username}[/green]\n"
                f"Password: [yellow]{password}[/yellow]"
            )
            console.print(Panel(body, title="Vault item", border_style="cyan"))
            if copy_with_timeout(password):
                console.print("[dim]Password copied to clipboard for 15 seconds.[/dim]")
            return

        if intent == "list":
            table, rows = self.list_folder(args[0] if args else None)
            if not rows:
                console.print(Panel("No saved passwords here yet.", title="Empty", border_style="yellow"))
                return
            console.print(table)
            return

        if intent == "find":
            rows = self.search_entries(args[0])
            if not rows:
                console.print(Panel(f"No matches for [bold]{args[0]}[/bold].", title="Search", border_style="yellow"))
                return
            table = Table(title=f"Matches for '{args[0]}'", box=box.ROUNDED, header_style="bold cyan")
            table.add_column("Folder", style="magenta")
            table.add_column("Service", style="white")
            table.add_column("Username", style="green")
            for row in rows:
                table.add_row(row["name"], row["service"], row["username"] or "-")
            console.print(table)
            return

        if intent == "move":
            changed, service, source, destination = self.move_entry(args[0], args[1], args[2])
            if not changed:
                console.print(Panel("I could not find that login in the source folder.", title="Move failed", border_style="red"))
                return
            console.print(Panel(f"[bold]{service}[/bold] moved from [magenta]{source}[/magenta] to [magenta]{destination}[/magenta].", title="Moved", border_style="green"))
            return

        if intent == "delete":
            changed, folder, service = self.delete_entry(args[0], args[1])
            if not changed:
                console.print(Panel("Nothing matched that delete request.", title="Delete failed", border_style="red"))
                return
            console.print(Panel(f"[bold]{service}[/bold] removed from [magenta]{folder}[/magenta].", title="Deleted", border_style="green"))
            return

        if intent == "remember":
            key, value = args
            self.remember_fact(key, value)
            console.print(Panel(f"I'll remember that [bold]{key}[/bold] is [green]{value}[/green].", title="Stored", border_style="green"))
            return

        if intent == "recall":
            value = self.recall_fact(args[0])
            if not value:
                console.print(Panel("I do not have that fact yet.", title="No match", border_style="yellow"))
                return
            console.print(Panel(f"[green]{value}[/green]", title=args[0], border_style="cyan"))
            return

        if intent == "generate":
            try:
                length = int(args[0])
                password = generate_password(length)
            except ValueError as exc:
                console.print(Panel(str(exc), title="Invalid length", border_style="red"))
                return
            console.print(Panel(f"[yellow]{password}[/yellow]", title=f"Generated password ({length})", border_style="cyan"))
            if copy_with_timeout(password):
                console.print("[dim]Password copied to clipboard for 15 seconds.[/dim]")
            return

        if intent == "copy":
            username, password, folder, service = self.get_entry(args[0], args[1])
            if not password:
                console.print(Panel("Nothing matched that copy request.", title="Copy failed", border_style="red"))
                return
            if copy_with_timeout(password):
                console.print(Panel(f"Copied [bold]{service}[/bold] from [magenta]{folder}[/magenta].", title="Clipboard", border_style="green"))
            else:
                console.print(Panel("Clipboard support is not available on this machine.", title="Clipboard unavailable", border_style="yellow"))
            return

        console.print(
            Panel(
                "Try `help`, `list all`, `save github in personal as ali`, or `what's my github password in personal`.",
                title="Command not understood",
                border_style="yellow",
            )
        )


def render_welcome():
    examples = "\n".join(f"- {example}" for example in COMMAND_EXAMPLES)
    message = (
        f"[bold cyan]{APP_NAME}[/bold cyan]\n"
        f"{APP_TAGLINE}\n\n"
        f"Vault file: [magenta]{VAULT}[/magenta]\n"
        f"Salt file: [magenta]{SALT}[/magenta]\n\n"
        f"[bold]Try these:[/bold]\n{examples}"
    )
    console.print(Panel(message, title="Welcome", border_style="blue"))


def render_session_banner(agent: NotionVaultCLI):
    folders, entries, facts = agent.counts()
    summary = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
    summary.add_column(style="cyan")
    summary.add_column(style="white")
    summary.add_row("Folders", str(folders))
    summary.add_row("Passwords", str(entries))
    summary.add_row("Facts", str(facts))

    hint = Text()
    hint.append("Type ", style="white")
    hint.append("help", style="bold cyan")
    hint.append(" for commands, ", style="white")
    hint.append("summary", style="bold cyan")
    hint.append(" for stats, or ", style="white")
    hint.append("quit", style="bold cyan")
    hint.append(" to lock the vault.", style="white")

    console.print(Panel(summary, title="Session", border_style="blue"))
    console.print(Panel(hint, title="Quick start", border_style="cyan"))


def prompt_session():
    if PTK:
        return PromptSession(history=FileHistory(str(HIST)))
    return None


def main():
    render_welcome()

    if not VAULT.exists():
        console.print(Panel("Create a master password to initialize your local vault.", title="First run", border_style="magenta"))
        first = getpass.getpass("Choose master password: ")
        second = getpass.getpass("Confirm master password: ")
        if first != second:
            console.print("[red]Master password mismatch.[/red]")
            return
        fernet = Fernet(derive_key(first))
        init_db()
    else:
        master = getpass.getpass("Master password: ")
        fernet = Fernet(derive_key(master))

    init_db()
    agent = NotionVaultCLI(fernet)
    if not agent.ensure_master_password():
        console.print("[red]Unable to unlock vault. Check your master password.[/red]")
        return
    render_session_banner(agent)
    session = prompt_session()

    while True:
        try:
            prompt_label = "vault> "
            text = session.prompt(prompt_label) if session else console.input(prompt_label)
            if text.lower().strip() in {"exit", "quit", "bye"}:
                break
            if not text.strip():
                continue
            agent.handle(text)
        except KeyboardInterrupt:
            console.print("\n[dim]Use `quit` to lock the vault.[/dim]")
            continue
        except EOFError:
            break
        except Exception as exc:
            console.print(Panel(str(exc), title="Error", border_style="red"))

    agent.close()
    console.print(Panel("Vault locked. See you next time.", title="Goodbye", border_style="blue"))


if __name__ == "__main__":
    main()
