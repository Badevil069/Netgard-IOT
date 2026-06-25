import os
import numpy as np
import pandas as pd
DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
CSV_PATH = os.path.join(DATA_DIR, 'live_traffic.csv')

def _compute_packets_per_second(group: pd.DataFrame) -> float:
    try:
        if len(group) < 2:
            return float(len(group))
        timestamps = pd.to_datetime(group['timestamp'], utc=True)
        duration = (timestamps.max() - timestamps.min()).total_seconds()
        if duration <= 0:
            return float(len(group))
        return len(group) / duration
    except Exception as exc:
        print(f'[features] Error computing packets_per_second: {exc}')
        return float(len(group))

def _compute_burst_score(group: pd.DataFrame) -> float:
    try:
        if len(group) < 2:
            return 0.0
        timestamps = pd.to_datetime(group['timestamp'], utc=True).sort_values()
        deltas = timestamps.diff().dropna().dt.total_seconds()
        if deltas.empty:
            return 0.0
        return float(deltas.std())
    except Exception as exc:
        print(f'[features] Error computing burst_score: {exc}')
        return 0.0

def extract_features(csv_path: str | None=None) -> pd.DataFrame:
    path = csv_path or CSV_PATH
    try:
        df = pd.read_csv(path)
        print(f'[features] Loaded {len(df)} packets from {path}')
    except FileNotFoundError:
        print(f'[features] ERROR: CSV file not found at {path}')
        print('[features] Run capture.py first to generate traffic data.')
        return pd.DataFrame(columns=['src_ip', 'packets_per_second', 'average_packet_size', 'unique_dst_ports', 'protocol_diversity', 'burst_score'])
    except pd.errors.EmptyDataError:
        print(f'[features] WARNING: CSV file is empty at {path}')
        return pd.DataFrame(columns=['src_ip', 'packets_per_second', 'average_packet_size', 'unique_dst_ports', 'protocol_diversity', 'burst_score'])
    except Exception as exc:
        print(f'[features] ERROR: Failed to read CSV - {exc}')
        return pd.DataFrame(columns=['src_ip', 'packets_per_second', 'average_packet_size', 'unique_dst_ports', 'protocol_diversity', 'burst_score'])
    if df.empty:
        print('[features] WARNING: No packets to process.')
        return pd.DataFrame(columns=['src_ip', 'packets_per_second', 'average_packet_size', 'unique_dst_ports', 'protocol_diversity', 'burst_score'])
    required = {'src_ip', 'timestamp', 'packet_size', 'dst_port', 'protocol'}
    missing = required - set(df.columns)
    if missing:
        print(f'[features] ERROR: Missing columns in CSV: {missing}')
        return pd.DataFrame()
    try:
        grouped = df.groupby('src_ip')
        feature_rows: list[dict] = []
        for src_ip, group in grouped:
            row = {'src_ip': src_ip, 'packets_per_second': round(_compute_packets_per_second(group), 4), 'average_packet_size': round(float(group['packet_size'].mean()), 2), 'unique_dst_ports': int(group['dst_port'].nunique()), 'protocol_diversity': int(group['protocol'].nunique()), 'burst_score': round(_compute_burst_score(group), 4)}
            feature_rows.append(row)
        features_df = pd.DataFrame(feature_rows)
        print(f'[features] Computed features for {len(features_df)} unique source IPs')
        print(features_df.to_string(index=False))
        return features_df
    except Exception as exc:
        print(f'[features] ERROR during feature extraction: {exc}')
        return pd.DataFrame()
if __name__ == '__main__':
    result = extract_features()
    if not result.empty:
        print('\n[features] Feature extraction complete.')
    else:
        print('\n[features] No features extracted - check the data file.')