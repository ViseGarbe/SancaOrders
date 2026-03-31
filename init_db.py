import sqlite3
from pathlib import Path

DB_PATH = "iot_auth.db"
SCHEMA_PATH = "schema.sql"

def main():
    if not Path(SCHEMA_PATH).exists():
        raise FileNotFoundError(f"File non trovato: {SCHEMA_PATH}")

    conn = sqlite3.connect(DB_PATH)
    try:
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema = f.read()
        conn.executescript(schema)
        conn.commit()
        print(f"Database creato correttamente: {DB_PATH}")
    finally:
        conn.close()

if __name__ == "__main__":
    main()