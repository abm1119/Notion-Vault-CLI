import sqlite3
import tempfile
import unittest
from pathlib import Path

import notion_vault_cli as nv


class VaultTestCase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.tmp_path = Path(self.temp_dir.name)
        self.original_vault = nv.VAULT
        self.original_salt = nv.SALT
        self.original_hist = nv.HIST
        nv.VAULT = self.tmp_path / "vault.db"
        nv.SALT = self.tmp_path / "vault.salt"
        nv.HIST = self.tmp_path / "vault.history"
        nv.init_db()
        self.fernet = nv.Fernet(nv.derive_key("correct horse battery staple"))
        self.agent = nv.NotionVaultCLI(self.fernet)

    def tearDown(self):
        self.agent.close()
        nv.VAULT = self.original_vault
        nv.SALT = self.original_salt
        nv.HIST = self.original_hist
        self.temp_dir.cleanup()

    def test_parse_multiword_commands(self):
        self.assertEqual(
            self.agent.parse("save notion vault in borlo labs as ali.work"),
            ("add", ["borlo labs", "notion vault", "ali.work"]),
        )
        self.assertEqual(
            self.agent.parse("what's my notion vault password in borlo labs"),
            ("get", ["borlo labs", "notion vault"]),
        )
        self.assertEqual(self.agent.parse("list borlo labs"), ("list", ["borlo labs"]))
        self.assertEqual(self.agent.parse("show passwords"), ("list", []))
        self.assertEqual(self.agent.parse("show github"), ("get", ["Personal", "github"]))

    def test_save_and_get_multiword_entry(self):
        folder, service, _ = self.agent.save_entry("borlo labs", "notion vault", "ali.work", "secret-123")
        username, password, resolved_folder, resolved_service = self.agent.get_entry("borlo labs", "notion vault")
        self.assertEqual(folder, "Borlo Labs")
        self.assertEqual(service, "notion vault")
        self.assertEqual(username, "ali.work")
        self.assertEqual(password, "secret-123")
        self.assertEqual(resolved_folder, "Borlo Labs")
        self.assertEqual(resolved_service, "notion vault")

    def test_init_db_migrates_legacy_schema(self):
        self.agent.close()
        conn = sqlite3.connect(nv.VAULT)
        conn.executescript(
            """
            DROP TABLE IF EXISTS meta;
            DROP TABLE IF EXISTS categories;
            DROP TABLE IF EXISTS entries;
            DROP TABLE IF EXISTS facts;
            DROP TABLE IF EXISTS audit;
            CREATE TABLE categories(id INTEGER PRIMARY KEY, name TEXT UNIQUE COLLATE NOCASE, created_at REAL);
            CREATE TABLE entries(id INTEGER PRIMARY KEY, category_id INTEGER, service TEXT COLLATE NOCASE, username TEXT, password BLOB, notes TEXT, created_at REAL, updated_at REAL, accessed_at REAL, UNIQUE(category_id, service), FOREIGN KEY(category_id) REFERENCES categories(id) ON DELETE CASCADE);
            CREATE TABLE facts(key TEXT PRIMARY KEY COLLATE NOCASE, value TEXT, updated_at REAL);
            CREATE TABLE audit(ts REAL, action TEXT, detail TEXT);
            """
        )
        conn.commit()
        conn.close()
        nv.init_db()
        conn = sqlite3.connect(nv.VAULT)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        conn.close()
        self.assertIn("meta", tables)
        self.agent = nv.NotionVaultCLI(self.fernet)

    def test_master_password_validation_rejects_wrong_key(self):
        self.agent.save_entry("personal", "github", "ali", "secret-123")
        self.assertTrue(self.agent.ensure_master_password())
        self.agent.close()

        wrong_fernet = nv.Fernet(nv.derive_key("totally wrong password"))
        wrong_agent = nv.NotionVaultCLI(wrong_fernet)
        try:
            self.assertFalse(wrong_agent.ensure_master_password())
        finally:
            wrong_agent.close()

        self.agent = nv.NotionVaultCLI(self.fernet)

    def test_generate_password_bounds(self):
        self.assertEqual(len(nv.generate_password(8)), 8)
        self.assertEqual(len(nv.generate_password(64)), 64)
        with self.assertRaises(ValueError):
            nv.generate_password(7)
        with self.assertRaises(ValueError):
            nv.generate_password(300)

    def test_stress_bulk_save_search_move_delete(self):
        for index in range(150):
            folder = f"client work {index % 5}"
            service = f"service portal {index}"
            username = f"user{index}@example.com"
            password = f"pw-{index:04d}"
            self.agent.save_entry(folder, service, username, password)

        folders, entries, _ = self.agent.counts()
        self.assertGreaterEqual(folders, 8)
        self.assertEqual(entries, 150)

        search_rows = self.agent.search_entries("portal 12")
        self.assertTrue(any(row["service"] == "service portal 12" for row in search_rows))

        changed, service, source, destination = self.agent.move_entry(
            "service portal 12",
            "client work 2",
            "archive team",
        )
        self.assertEqual(changed, 1)
        self.assertEqual(service, "service portal 12")
        self.assertEqual(source, "Client Work 2")
        self.assertEqual(destination, "Archive Team")

        username, password, folder, service = self.agent.get_entry("archive team", "service portal 12")
        self.assertEqual(username, "user12@example.com")
        self.assertEqual(password, "pw-0012")
        self.assertEqual(folder, "Archive Team")
        self.assertEqual(service, "service portal 12")

        deleted, folder, service = self.agent.delete_entry("archive team", "service portal 12")
        self.assertEqual(deleted, 1)
        self.assertEqual(folder, "Archive Team")
        self.assertEqual(service, "service portal 12")
        username, password, _, _ = self.agent.get_entry("archive team", "service portal 12")
        self.assertIsNone(username)
        self.assertIsNone(password)


if __name__ == "__main__":
    unittest.main()
