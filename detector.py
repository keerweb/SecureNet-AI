import os
import sqlite3
from datetime import datetime

import joblib
import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(ROOT, "model", "securenet_rf_model.pkl")
FEATURE_PATH = os.path.join(ROOT, "model", "securenet_feature_list.pkl")
FLOW_FILE = os.path.join(ROOT, "capture", "live_flows.csv")
DB_PATH = os.path.join(ROOT, "database", "securenet.db")

MAPPING = {
    "Destination Port":"dst_port",
    "Flow Duration":"flow_duration",
    "Total Fwd Packets":"tot_fwd_pkts",
    "Total Backward Packets":"tot_bwd_pkts",
    "Total Length of Fwd Packets":"totlen_fwd_pkts",
    "Total Length of Bwd Packets":"totlen_bwd_pkts",
    "Fwd Packet Length Max":"fwd_pkt_len_max",
    "Fwd Packet Length Min":"fwd_pkt_len_min",
    "Fwd Packet Length Mean":"fwd_pkt_len_mean",
    "Fwd Packet Length Std":"fwd_pkt_len_std",
    "Bwd Packet Length Max":"bwd_pkt_len_max",
    "Bwd Packet Length Min":"bwd_pkt_len_min",
    "Bwd Packet Length Mean":"bwd_pkt_len_mean",
    "Bwd Packet Length Std":"bwd_pkt_len_std",
    "Flow Bytes/s":"flow_byts_s",
    "Flow Packets/s":"flow_pkts_s",
    "Flow IAT Mean":"flow_iat_mean",
    "Flow IAT Std":"flow_iat_std",
    "Flow IAT Max":"flow_iat_max",
    "Flow IAT Min":"flow_iat_min",
    "Fwd IAT Total":"fwd_iat_tot",
    "Fwd IAT Mean":"fwd_iat_mean",
    "Fwd IAT Std":"fwd_iat_std",
    "Fwd IAT Max":"fwd_iat_max",
    "Fwd IAT Min":"fwd_iat_min",
    "Bwd IAT Total":"bwd_iat_tot",
    "Bwd IAT Mean":"bwd_iat_mean",
    "Bwd IAT Std":"bwd_iat_std",
    "Bwd IAT Max":"bwd_iat_max",
    "Bwd IAT Min":"bwd_iat_min",
    "Fwd PSH Flags":"fwd_psh_flags",
    "Bwd PSH Flags":"bwd_psh_flags",
    "Fwd URG Flags":"fwd_urg_flags",
    "Bwd URG Flags":"bwd_urg_flags",
    "Fwd Header Length":"fwd_header_len",
    "Bwd Header Length":"bwd_header_len",
    "Fwd Packets/s":"fwd_pkts_s",
    "Bwd Packets/s":"bwd_pkts_s",
    "Min Packet Length":"pkt_len_min",
    "Max Packet Length":"pkt_len_max",
    "Packet Length Mean":"pkt_len_mean",
    "Packet Length Std":"pkt_len_std",
    "Packet Length Variance":"pkt_len_var",
    "FIN Flag Count":"fin_flag_cnt",
    "SYN Flag Count":"syn_flag_cnt",
    "RST Flag Count":"rst_flag_cnt",
    "PSH Flag Count":"psh_flag_cnt",
    "ACK Flag Count":"ack_flag_cnt",
    "URG Flag Count":"urg_flag_cnt",
    "CWE Flag Count":"cwr_flag_count",
    "ECE Flag Count":"ece_flag_cnt",
    "Down/Up Ratio":"down_up_ratio",
    "Average Packet Size":"pkt_size_avg",
    "Avg Fwd Segment Size":"fwd_seg_size_avg",
    "Avg Bwd Segment Size":"bwd_seg_size_avg",
    "Fwd Header Length.1":"fwd_header_len",
    "Fwd Avg Bytes/Bulk":"fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk":"fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate":"fwd_blk_rate_avg",
    "Bwd Avg Bytes/Bulk":"bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk":"bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate":"bwd_blk_rate_avg",
    "Subflow Fwd Packets":"subflow_fwd_pkts",
    "Subflow Bwd Packets":"subflow_bwd_pkts",
    "Subflow Fwd Bytes":"subflow_fwd_byts",
    "Subflow Bwd Bytes":"subflow_bwd_byts",
    "Init_Win_bytes_forward":"init_fwd_win_byts",
    "Init_Win_bytes_backward":"init_bwd_win_byts",
    "act_data_pkt_fwd":"fwd_act_data_pkts",
    "min_seg_size_forward":"fwd_seg_size_min",
    "Active Mean":"active_mean",
    "Active Std":"active_std",
    "Active Max":"active_max",
    "Active Min":"active_min",
    "Idle Mean":"idle_mean",
    "Idle Std":"idle_std",
    "Idle Max":"idle_max",
    "Idle Min":"idle_min",
}

def init_db():
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

def predict_file(flow_file=FLOW_FILE):
    if not os.path.exists(flow_file):
        raise FileNotFoundError(f"Flow CSV not found: {flow_file}")
    model = joblib.load(MODEL_PATH)
    features = list(joblib.load(FEATURE_PATH))
    df = pd.read_csv(flow_file)

    missing = [f for f in features if MAPPING.get(f) not in df.columns]
    if missing:
        raise ValueError("Missing mapped columns: " + ", ".join(missing))

    X = pd.DataFrame({
        f: pd.to_numeric(df[MAPPING[f]], errors="coerce")
        for f in features
    })
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    pred = model.predict(X)
    proba = model.predict_proba(X)
    confidence = np.max(proba, axis=1) * 100
    run_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    records = []
    for i in range(len(df)):
        records.append({
            "run_time": run_time,
            "src_ip": str(df.iloc[i].get("src_ip", "")),
            "dst_ip": str(df.iloc[i].get("dst_ip", "")),
            "src_port": int(float(df.iloc[i].get("src_port", 0))),
            "dst_port": int(float(df.iloc[i].get("dst_port", 0))),
            "protocol": str(df.iloc[i].get("protocol", "")),
            "prediction": "DDoS" if int(pred[i]) == 1 else "BENIGN",
            "confidence": round(float(confidence[i]), 2),
        })

    init_db()
    with sqlite3.connect(DB_PATH) as con:
        # Keep the latest run clean for a simple student demo.
        con.execute("DELETE FROM detections")
        con.executemany("""
            INSERT INTO detections
            (run_time, src_ip, dst_ip, src_port, dst_port, protocol, prediction, confidence)
            VALUES (:run_time, :src_ip, :dst_ip, :src_port, :dst_port,
                    :protocol, :prediction, :confidence)
        """, records)

    return records
