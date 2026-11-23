import pandas as pd
import joblib
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DATASET = os.path.join(
    ROOT,
    "MachineLearningCVE",
    "Friday-WorkingHours-Afternoon-DDoS.pcap_ISCX.csv"
)

MODEL_FILE = os.path.join(
    ROOT,
    "model",
    "securenet_rf_model.pkl"
)

FEATURE_FILE = os.path.join(
    ROOT,
    "model",
    "securenet_feature_list.pkl"
)

OUTPUT = os.path.join(
    ROOT,
    "capture",
    "live_flows.csv"
)

print("Loading CICIDS2017 DDoS dataset...")

df = pd.read_csv(DATASET)
df.columns = df.columns.str.strip()

# Select 20 DDoS flows
ddos = df[df["Label"] == "DDoS"].sample(
    20,
    random_state=42
).copy()

print("DDoS samples selected:", len(ddos))

# Load model feature list
features = list(joblib.load(FEATURE_FILE))

# CICIDS2017 -> CICFlowMeter column mapping
mapping = {
    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration",
    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",
    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",
    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",
    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",
    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",
    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",
    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",
    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",
    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",
    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",
    "Fwd Header Length": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",
    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",
    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",
    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",
    "CWE Flag Count": "cwr_flag_count",
    "ECE Flag Count": "ece_flag_cnt",
    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",
    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",
    "Fwd Header Length.1": "fwd_header_len",
    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",
    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",
    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",
    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",
    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",
    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",
    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min"
}

# Check all model features exist in dataset
missing = [f for f in features if f not in mapping]

if missing:
    print("ERROR: Missing mappings:")
    print(missing)
    raise SystemExit

# Create output in CICFlowMeter-style format
out = pd.DataFrame()

# CICIDS2017 ML CSV does not contain source/destination IP or protocol.
# These are only display fields for our demo.
out["src_ip"] = ["CICIDS2017-DDoS"] * len(ddos)
out["dst_ip"] = ["Test-Server"] * len(ddos)
out["src_port"] = [0] * len(ddos)

# Destination Port exists in CICIDS2017
out["dst_port"] = pd.to_numeric(
    ddos["Destination Port"],
    errors="coerce"
).fillna(0)

# Protocol is not available in this CICIDS2017 ML CSV,
# so use a display value only.
out["protocol"] = ["Dataset-DDoS"] * len(ddos)

# Add all 78 model features
for feature in features:
    column = mapping[feature]

    out[column] = pd.to_numeric(
        ddos[feature],
        errors="coerce"
    ).fillna(0).values

# Save demo flow file
out.to_csv(OUTPUT, index=False)

print()
print("=" * 50)
print("DDoS DEMO FILE CREATED SUCCESSFULLY")
print("=" * 50)
print("Flows created :", len(out))
print("Model features:", len(features))
print("Output file   :", OUTPUT)
print("=" * 50)