from flask import Flask, render_template, jsonify
from detection.detector import predict_file, init_db, DB_PATH
import sqlite3
import os

app = Flask(__name__)
init_db()

def get_data():
    with sqlite3.connect(DB_PATH) as con:
        con.row_factory = sqlite3.Row
        rows = con.execute(
            "SELECT * FROM detections ORDER BY id DESC"
        ).fetchall()
    return [dict(r) for r in rows]

@app.route("/")
def home():
    data = get_data()
    total = len(data)
    ddos = sum(r["prediction"] == "DDoS" for r in data)
    benign = total - ddos
    return render_template(
        "index.html",
        total=total,
        benign=benign,
        ddos=ddos,
        status="ALERT" if ddos else "NORMAL",
        rows=data
    )

@app.route("/refresh")
def refresh():
    try:
        predict_file()
        return jsonify({"ok": True, "message": "Prediction refreshed"})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True)
