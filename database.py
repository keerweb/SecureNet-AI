import os
import sqlite3

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(ROOT, "database", "securenet.db")

def create_database():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with sqlite3.connect(DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS detections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_time TEXT NOT NULL,
                src_ip TEXT,
                dst_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                protocol TEXT,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL
            )
        """)
    print("SecureNet AI database ready:", DB_PATH)

if __name__ == "__main__":
    create_database()
