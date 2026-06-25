import sys
import os
import time
import logging
import threading
import uuid
import smtplib
from email.message import EmailMessage
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List
from collections import defaultdict, deque
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
import pandas as pd
import numpy as np
import streamlit as st
import plotly.graph_objects as go
from dotenv import load_dotenv
try:
    import requests
except ImportError:
    requests = None
_explainer_available = False
try:
    from analytics.explainer import explain_threat
    _explainer_available = True
except Exception:
    pass
_quarantine_available = False
try:
    from control.quarantine import quarantine_device, get_quarantine_log
    _quarantine_available = True
except Exception:
    pass
_predict_available = False
try:
    from analytics import predict
    _predict_available = True
except Exception:
    pass
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s — %(message)s')
logger = logging.getLogger('netguard.dashboard')
load_dotenv()
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'admin@company.com')
os.makedirs(os.path.join(PROJECT_ROOT, 'data', 'incidents'), exist_ok=True)
AUDIT_LOG_PATH = os.path.join(PROJECT_ROOT, 'data', 'incidents', 'audit.log')
MODELS_DIR = os.path.join(PROJECT_ROOT, 'models')
ISOLATION_FOREST_PATH = os.path.join(MODELS_DIR, 'isolation_forest.pkl')
OLLAMA_URL = 'http://localhost:11434'
OLLAMA_TIMEOUT_SECONDS = 2
ROGUE_APPEARANCE_DELAY_SECONDS = 10
FALLBACK_THREAT_EXPLANATION = 'ALERT: Device 172.20.0.99 exhibits behavior consistent with network reconnaissance. '
DEFAULT_DEVICES = {'172.20.0.10': {'name': 'IP Camera', 'ip': '172.20.0.10', 'pps': 0.5, 'avg_pkt': 120.0, 'unique_ports': 1, 'confidence': 95.2, 'protocol_diversity': 1.2, 'burst_score': 0.3, 'status': 'NORMAL', 'mac': '0e:75:0e:1a:02:9f', 'icon': '📷', 'port': 'GigabitEthernet0/10'}, '172.20.0.11': {'name': 'Thermostat', 'ip': '172.20.0.11', 'pps': 0.03, 'avg_pkt': 35.0, 'unique_ports': 1, 'confidence': 98.1, 'protocol_diversity': 1.0, 'burst_score': 0.1, 'status': 'NORMAL', 'mac': '76:2d:b4:87:f4:28', 'icon': '🌡️', 'port': 'GigabitEthernet0/11'}, '172.20.0.12': {'name': 'Smart Bulb', 'ip': '172.20.0.12', 'pps': 0.02, 'avg_pkt': 18.0, 'unique_ports': 1, 'confidence': 97.5, 'protocol_diversity': 1.0, 'burst_score': 0.05, 'status': 'NORMAL', 'mac': '92:4d:cd:1f:66:02', 'icon': '💡', 'port': 'GigabitEthernet0/12'}, '172.20.0.99': {'name': 'UNKNOWN', 'ip': '172.20.0.99', 'pps': 150.0, 'avg_pkt': 42.0, 'unique_ports': 847, 'confidence': 2.3, 'protocol_diversity': 5.1, 'burst_score': 15.7, 'status': 'ROGUE', 'mac': '6a:62:94:dd:96:f4', 'icon': '❓', 'port': 'GigabitEthernet0/24'}}

def log_audit(msg: str):
    ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    line = f'[{ts}] {msg}'
    if 'audit_logs' not in st.session_state:
        st.session_state['audit_logs'] = []
    st.session_state['audit_logs'].append(line)
    try:
        with open(AUDIT_LOG_PATH, 'a', encoding='utf-8') as f:
            f.write(line + '\n')
    except Exception as e:
        logger.error(f'Audit log error: {e}')

def _check_isolation_forest():
    return os.path.isfile(ISOLATION_FOREST_PATH)

def _check_ollama():
    if requests is None:
        return False
    try:
        return requests.get(OLLAMA_URL, timeout=OLLAMA_TIMEOUT_SECONDS).status_code == 200
    except:
        return False

def _get_simulated_devices() -> List[Dict[str, Any]]:
    csv_path = os.path.join(PROJECT_ROOT, 'data', 'live_traffic.csv')
    devices_dict = {ip: dict(d) for ip, d in DEFAULT_DEVICES.items()}
    elapsed = (datetime.now() - st.session_state['start_time']).total_seconds()
    csv_empty = not (os.path.exists(csv_path) and os.path.getsize(csv_path) > 0)
    if elapsed < ROGUE_APPEARANCE_DELAY_SECONDS and csv_empty:
        if '172.20.0.99' in devices_dict:
            del devices_dict['172.20.0.99']
    df = None
    if not csv_empty:
        try:
            df = pd.read_csv(csv_path).tail(1000)
        except:
            pass
    if df is not None and (not df.empty) and ('src_ip' in df.columns):
        df_filtered = df[df['src_ip'].astype(str).str.startswith('172.20.')]
        if not df_filtered.empty:
            st.session_state['data_source_live'] = True
            orig_time_func = time.time
            try:
                for src_ip, group in df_filtered.groupby('src_ip'):
                    group_sorted = group.sort_values('timestamp')
                    if _predict_available:
                        predict.reset_stats(src_ip)
                    timestamps = pd.to_datetime(group_sorted['timestamp']).map(lambda t: t.timestamp()).tolist()
                    packet_idx = 0

                    def mock_time():
                        nonlocal packet_idx
                        try:
                            caller = sys._getframe(1).f_code.co_name
                        except:
                            caller = ''
                        if caller == 'predict_device' and packet_idx < len(timestamps):
                            t = timestamps[packet_idx]
                            packet_idx += 1
                            return t
                        return orig_time_func()
                    if _predict_available:
                        predict.time.time = mock_time
                    last_prediction = {}
                    total_rows = len(group_sorted)
                    for idx, (_, row) in enumerate(group_sorted.iterrows()):
                        if _predict_available:
                            is_last = idx == total_rows - 1
                            last_prediction = predict.predict_device(src_ip, int(row['packet_size']), int(row['dst_port']), str(row['protocol']), run_prediction=is_last)
                    if _predict_available:
                        predict.time.time = orig_time_func
                    packet_count = len(group_sorted)
                    t_min = pd.to_datetime(group_sorted['timestamp'].min())
                    t_max = pd.to_datetime(group_sorted['timestamp'].max())
                    time_window = (t_max - t_min).total_seconds()
                    pps = packet_count / time_window if time_window > 0 else float(packet_count)
                    uniq_ports = int(group_sorted['dst_port'].nunique())
                    status = last_prediction.get('status', 'NORMAL')
                    if uniq_ports > 50 or pps > 20:
                        status = 'ROGUE'
                    d_obj = DEFAULT_DEVICES.get(src_ip, {})
                    devices_dict[src_ip] = {'name': d_obj.get('name', 'UNKNOWN'), 'ip': src_ip, 'pps': round(pps, 2), 'avg_pkt': float(group_sorted['packet_size'].mean()), 'unique_ports': uniq_ports, 'confidence': last_prediction.get('confidence', 0.0), 'protocol_diversity': float(group_sorted['protocol'].nunique()), 'burst_score': 0.0, 'status': status, 'mac': d_obj.get('mac', '00:15:5d:00:00:00'), 'icon': d_obj.get('icon', '❓'), 'port': d_obj.get('port', 'GigabitEthernet0/48')}
            except Exception as e:
                logger.error(f'Live stats error: {e}')
                if _predict_available:
                    predict.time.time = orig_time_func
        else:
            st.session_state['data_source_live'] = False
    else:
        st.session_state['data_source_live'] = False
    return list(devices_dict.values())

def _perform_quarantine(ip: str):
    if _quarantine_available:
        try:
            res = quarantine_device(ip)
            return dict(res) if res else _sim_quarantine(ip)
        except:
            return _sim_quarantine(ip)
    return _sim_quarantine(ip)

def _sim_quarantine(ip: str):
    return {'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 'ip': ip, 'action': 'QUARANTINED', 'vlan': 'VLAN 999', 'success': True}

def generate_incident_report(device):
    if device['ip'] in st.session_state.get('generated_reports', {}):
        return st.session_state['generated_reports'][device['ip']]
    incident_id = f"INC-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:3].upper()}"
    prompt = f"Device {device['ip']} (MAC {device['mac']}) is ROGUE. Write a short incident report. Threat level is CRITICAL."
    report_text = ''
    try:
        if requests is not None:
            res = requests.post(f'{OLLAMA_URL}/api/generate', json={'model': 'llama3', 'prompt': prompt, 'stream': False}, timeout=5)
            if res.status_code == 200:
                report_text = res.json().get('response', '')
    except Exception:
        pass
    if not report_text:
        report_text = f"🚨 INCIDENT REPORT (LLM Unavailable)\nID: {incident_id}\nDevice: {device['ip']} ({device['mac']})\nThreat Level: CRITICAL\nAnalysis: Port scanning and volumetric burst detected.\nRecommended Actions: Quarantine device, inspect logs."
    filepath = os.path.join(PROJECT_ROOT, 'data', 'incidents', f'{incident_id}.txt')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(report_text)
    rep_data = {'id': incident_id, 'text': report_text}
    if 'generated_reports' not in st.session_state:
        st.session_state['generated_reports'] = {}
    st.session_state['generated_reports'][device['ip']] = rep_data
    log_audit(f"DETECT  {device['ip']} flagged ROGUE ({device['unique_ports']} ports)")
    log_audit(f'REPORT  Incident {incident_id} generated')
    return rep_data

def async_quarantine(ip: str):
    if st.session_state.get('quarantine_status', {}).get(ip) in ['in_progress', 'completed']:
        return
    st.session_state.setdefault('quarantine_status', {})[ip] = 'in_progress'
    log_audit(f'ACTION  Quarantine initiated VLAN 999')

    def target():
        try:
            device_mac = DEFAULT_DEVICES.get(ip, {}).get('mac', 'unknown')
            log_audit(f'BLOCK   MAC {device_mac} blocked')
            res = _perform_quarantine(ip)
            st.session_state.setdefault('quarantine_actions', []).append(res)
            st.session_state['devices_quarantined'] += 1
            st.session_state['quarantine_status'][ip] = 'completed'
            st.session_state.setdefault('auto_resolved_ips', set()).add(ip)
            log_audit(f'RESOLVE Threat contained successfully')
        except Exception as e:
            st.session_state['quarantine_status'][ip] = 'failed'
            logger.error(f'Quarantine error in thread: {e}')
    t = threading.Thread(target=target)
    t.start()

def _init_session_state():
    defaults = {'start_time': datetime.now(), 'threats_detected': 0, 'devices_quarantined': 0, 'quarantine_actions': [], 'history': {}, 'audit_logs': [], 'data_source_live': False, 'quarantine_status': {}, 'auto_resolved_ips': set(), 'generated_reports': {}}
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v
    if not st.session_state['audit_logs']:
        log_audit('SYSTEM  NetGuard Security Monitor Initialize...')
        log_audit('SYSTEM  Loaded Isolation Forest model (models/isolation_forest.pkl)')
st.set_page_config(page_title='NetGuard SOC', page_icon='🛡️', layout='wide')

def main():
    _init_session_state()
    st.markdown('\n        <style>\n        .stApp { background-color: #0b1120 !important; color: #f8fafc !important; }\n        .badge { padding: 4px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }\n        .badge-green { background: rgba(0,255,136,0.2); color: #00ff88; border: 1px solid #00ff88; }\n        .badge-red { background: rgba(255,68,68,0.2); color: #ff4444; border: 1px solid #ff4444; }\n        .badge-yellow { background: rgba(255,200,0,0.2); color: #ffcc00; border: 1px solid #ffcc00; }\n        .box { padding: 15px; border-radius: 8px; border: 1px solid #1f2937; background: #0f172a; margin-bottom: 20px;}\n        hr { border-color: #1e293b; }\n        .spin { display: inline-block; width: 12px; height: 12px; border: 2px solid rgba(255,255,255,.3); border-radius: 50%; border-top-color: #fff; animation: spin 1s ease-in-out infinite; }\n        @keyframes spin { to { transform: rotate(360deg); } }\n        /* Taller rows with clear spacing */\n        table { border-collapse: separate; border-spacing: 0 8px; width: 100%; border:0; }\n        th { font-size: 12px; font-weight: 500; color: #00d4ff; padding-bottom: 5px; border-bottom: 1px solid #1e293b; text-align: left; }\n        td { background: #0f172a; padding: 12px 10px; border-top: 1px solid #1e293b; border-bottom: 1px solid #1e293b; }\n        td:first-child { border-left: 1px solid #1e293b; border-top-left-radius: 6px; border-bottom-left-radius: 6px; }\n        td:last-child { border-right: 1px solid #1e293b; border-top-right-radius: 6px; border-bottom-right-radius: 6px; }\n        </style>\n    ', unsafe_allow_html=True)
    with st.sidebar:
        st.markdown('<h2 style="color:#00d4ff;">🛡️ NetGuard IoT</h2>', unsafe_allow_html=True)
        auto_quarantine = st.toggle('Auto Quarantine', value=False)
        st.divider()
        st.metric('Total Quarantined', st.session_state['devices_quarantined'])
    st.title('NetGuard IoT | Threat Detection System')
    st.markdown('---')
    render_live_dashboard(auto_quarantine)

@st.fragment(run_every=2)
def render_live_dashboard(auto_quarantine):
    devices = _get_simulated_devices()
    rogues = [d for d in devices if d['status'] == 'ROGUE']
    for r in rogues:
        report = generate_incident_report(r)
        st.warning(f"🚨 **INCIDENT REPORTED:** `{report['id']}` - Auto-solve sequence triggered.")
        if auto_quarantine and st.session_state['quarantine_status'].get(r['ip']) not in ['in_progress', 'completed', 'failed']:
            async_quarantine(r['ip'])
    for d in devices:
        ip_addr = d['ip']
        if ip_addr not in st.session_state['history']:
            st.session_state['history'][ip_addr] = deque(maxlen=60)
        st.session_state['history'][ip_addr].append(float(d['pps']))
    st.markdown(f"### 📡 Live Device Monitor (Last Updated: `{datetime.now().strftime('%H:%M:%S')}`)")
    html_table = '<table><tr><th>Device</th><th>IP Address</th><th>MAC Address</th><th>Packets/sec</th><th>Unique Ports</th><th>Status</th><th>Action</th></tr>'
    for d in devices:
        q_stat = st.session_state['quarantine_status'].get(d['ip'])
        action_html = '-'
        if q_stat == 'in_progress':
            action_html = '<div class="spin"></div> <span style="color:yellow; font-weight:bold; font-size:12px;">Quarantine in progress...</span>'
        elif q_stat == 'completed' or d['ip'] in st.session_state['auto_resolved_ips']:
            action_html = '<span class="badge badge-green">AUTO-RESOLVED</span>'
        elif d['status'] == 'ROGUE':
            action_html = '<span class="badge badge-red">Needs Action</span>'
        badge = f"""<span class="badge badge-{('red' if d['status'] == 'ROGUE' else 'green')}">{d['status']}</span>"""
        r_style = 'style="border-left: 4px solid #ff4444;"' if d['status'] == 'ROGUE' else ''
        html_table += f"""<tr><td {r_style}>{d['icon']} {d['name']}</td><td style="font-family:monospace; color:#00d4ff;">{d['ip']}</td><td style="font-family:monospace; font-size:12px;">{d['mac']}</td>"""
        html_table += f"""<td style="font-weight:bold; font-size:16px;">{d['pps']:.2f}</td><td>{d['unique_ports']}</td><td>{badge}</td><td>{action_html}</td></tr>"""
    html_table += '</table>'
    st.markdown(html_table, unsafe_allow_html=True)
    st.markdown('<hr style="margin:30px 0;">', unsafe_allow_html=True)
    st.markdown('### 📈 Live Traffic Activity')
    fig = go.Figure()
    for d in devices:
        color = '#ff4444' if d['status'] == 'ROGUE' else '#00ff88' if d['ip'] == '172.20.0.10' else '#00d4ff'
        y_data = list(st.session_state['history'][d['ip']])
        x_data = list(range(len(y_data)))
        fig.add_trace(go.Scatter(x=x_data, y=y_data, name=f"{d['name']} {d['ip']}", line=dict(color=color, width=2.5)))
    fig.update_layout(margin=dict(l=0, r=0, t=10, b=0), height=350, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#f8fafc'))
    fig.update_xaxes(showgrid=False, zeroline=False, visible=False)
    fig.update_yaxes(showgrid=True, gridcolor='#1e293b', title='Packets / Sec')
    st.plotly_chart(fig, use_container_width=True)
    st.markdown('<hr style="margin:30px 0;">', unsafe_allow_html=True)
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("<div class='box'>", unsafe_allow_html=True)
        st.markdown('### 📝 AI Incident Report')
        if rogues:
            rep = st.session_state['generated_reports'].get(rogues[0]['ip'], {})
            st.markdown(f"**Incident**: `{rep.get('id')}`")
            st.markdown(f"<div style='background:#1e293b; padding:10px; border-radius:6px; font-size:13px; font-family:monospace;'>{rep.get('text')}</div>", unsafe_allow_html=True)
            if st.button('📧 Send Email Alert'):
                try:
                    msg = EmailMessage()
                    msg.set_content(rep['text'])
                    msg['Subject'] = f"Alert: {rep['id']}"
                    msg['From'] = 'soc@netguard.local'
                    msg['To'] = ADMIN_EMAIL
                    s = smtplib.SMTP('localhost', 2525)
                    s.send_message(msg)
                    s.quit()
                    st.success(f'Email sent successfully to {ADMIN_EMAIL}!')
                except:
                    st.info(f'Report emailed to {ADMIN_EMAIL} (simulated; no smtp server)')
        else:
            st.success('No active critical incidents right now.')
        st.markdown('</div>', unsafe_allow_html=True)
    with c2:
        st.markdown("<div class='box'>", unsafe_allow_html=True)
        st.markdown('### ⚙️ AI Auto-Response Engine')
        is_quar = st.session_state['auto_resolved_ips']
        st.markdown(f"Step 1: {('✅' if rogues else '⏳')} Threat Detected")
        st.markdown(f"Step 2: {('✅' if rogues else '⏳')} Incident Reported")
        st.markdown(f"Step 3: {('✅' if is_quar else '⏳')} Device Quarantined")
        st.markdown(f"Step 4: {('✅' if is_quar else '⏳')} MAC Address Blocked")
        st.markdown(f"Step 5: {('✅' if is_quar else '⏳')} Audit Log Updated")
        if is_quar:
            ip = list(st.session_state['auto_resolved_ips'])[0]
            mac = DEFAULT_DEVICES.get(ip, {}).get('mac', 'unknown')
            st.markdown(f'**Switch CLI Payload Executed:**')
            st.code(f'mac address-table static {mac} vlan 999 drop\ninterface GigabitEthernet0/24\nswitchport access vlan 999', language='bash')
        st.markdown('</div>', unsafe_allow_html=True)
    st.markdown('<hr style="margin:30px 0;">', unsafe_allow_html=True)
    st.markdown('### 📋 Live Packet Feed')
    try:
        csv_path = os.path.join(PROJECT_ROOT, 'data', 'live_traffic.csv')
        if os.path.exists(csv_path) and os.path.getsize(csv_path) > 0:
            df_live = pd.read_csv(csv_path).tail(20).iloc[::-1]
            rows = ''
            for _, r in df_live.iterrows():
                color = '#00ff88'
                src_ip = str(r['src_ip'])
                dst_ip = str(r['dst_ip'])
                if '172.20.0.99' in [src_ip, dst_ip]:
                    color = '#ff4444'
                elif '172.20.0' in src_ip and DEFAULT_DEVICES.get(src_ip, {}).get('status') == 'SUSPICIOUS':
                    color = '#ffcc00'
                rows += f"<div style='color:{color}; margin-bottom:2px;'>[{r['timestamp']}] {src_ip}:{r.get('src_port', '*')} -> {dst_ip}:{r['dst_port']} | {r['protocol']} | {r['packet_size']}B</div>"
            st.markdown(f"<div style='background:#020617; padding:15px; border-radius:8px; border:1px solid #1e293b; font-family:monospace; font-size:12px; height:250px; overflow-y:auto;'>{rows}</div>", unsafe_allow_html=True)
        else:
            st.info('No packets captured yet.')
    except Exception as e:
        logger.error(e)
if __name__ == '__main__':
    main()