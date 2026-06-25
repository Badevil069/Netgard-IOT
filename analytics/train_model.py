import os
import pickle
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, accuracy_score
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(PROJECT_ROOT, 'models')
MODEL_PATH = os.path.join(MODEL_DIR, 'isolation_forest.pkl')

def generate_synthetic_data() -> tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed=42)
    normal_pps = rng.uniform(0.1, 1.0, 500)
    normal_pkt_size = rng.uniform(50, 200, 500)
    normal_ports = rng.integers(1, 4, 500).astype(float)
    normal_proto = rng.integers(1, 3, 500).astype(float)
    normal_burst = rng.uniform(0.1, 0.5, 500)
    normal = np.column_stack([normal_pps, normal_pkt_size, normal_ports, normal_proto, normal_burst])
    rogue_pps = rng.uniform(50, 200, 100)
    rogue_pkt_size = rng.uniform(20, 60, 100)
    rogue_ports = rng.integers(100, 1001, 100).astype(float)
    rogue_proto = rng.integers(3, 7, 100).astype(float)
    rogue_burst = rng.uniform(5.0, 20.0, 100)
    rogue = np.column_stack([rogue_pps, rogue_pkt_size, rogue_ports, rogue_proto, rogue_burst])
    X = np.vstack([normal, rogue])
    y = np.array([1] * 500 + [-1] * 100)
    print(f'[train] Generated synthetic data: {len(normal)} normal + {len(rogue)} rogue = {len(X)} samples')
    return (X, y)

def train_model() -> IsolationForest:
    X, y_true = generate_synthetic_data()
    print('[train] Training IsolationForest model...')
    print('[train]   n_estimators  = 100')
    print('[train]   contamination = 0.1')
    print('[train]   random_state  = 42')
    model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    try:
        model.fit(X)
    except Exception as exc:
        print(f'[train] ERROR: Model training failed — {exc}')
        raise
    try:
        y_pred = model.predict(X)
        accuracy = accuracy_score(y_true, y_pred)
        print(f'\n[train] Training-set accuracy: {accuracy:.2%}')
        target_names = ['Rogue (-1)', 'Normal (1)']
        report = classification_report(y_true, y_pred, target_names=target_names)
        print(f'\n[train] Classification report:\n{report}')
        n_rogue_detected = int((y_pred == -1).sum())
        n_normal_detected = int((y_pred == 1).sum())
        print(f'[train] Predictions: Normal: {n_normal_detected}, Rogue: {n_rogue_detected}')
    except Exception as exc:
        print(f'[train] WARNING: Evaluation failed: {exc}')
    try:
        os.makedirs(MODEL_DIR, exist_ok=True)
        with open(MODEL_PATH, 'wb') as fh:
            pickle.dump(model, fh)
        print(f'\n[train] Model saved to {MODEL_PATH}')
    except OSError as exc:
        print(f'[train] ERROR: Failed to save model: {exc}')
        raise
    print('[train] Training complete')
    return model
if __name__ == '__main__':
    train_model()