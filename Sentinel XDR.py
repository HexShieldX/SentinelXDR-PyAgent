import os
import time
import psutil
import threading
from datetime import datetime
from collections import deque
import pandas as pd
import plotly.express as px
from dash import Dash, dcc, html, Input, Output
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass

# ==================== CONFIG ====================
MONITORED_DIR = os.path.expanduser("~")  # Home directory
IGNORED_EXTENSIONS = ['.tmp', '.log', '.ldb', '.sqlite', '.dat', '.lock', '.exe']
IGNORED_KEYWORDS = ['AppData\\Local', 'Microsoft\\Edge', 'Windows', 'System32', 'EBWebView', 'CustomDestinations', '.git']
MAX_EVENT_BUFFER = 500
MAX_CRITICAL_EVENTS = 100
LOG_FILE = "siem_events.log"

# Threat scoring
THREAT_SCORES = {
    "CMD Opened": 8,
    "File Deleted": 7,
    "File Modified": 4,
    "Process Started": 2,
    "Anomaly Detected": 9
}

EVENT_BURST_WINDOW = deque(maxlen=20)

# ==================== GLOBAL STATE ====================
EVENT_BUFFER = deque(maxlen=MAX_EVENT_BUFFER)
CRITICAL_EVENTS = deque(maxlen=MAX_CRITICAL_EVENTS)
START_TIME = datetime.now()
SEEN_PIDS = set()

# ==================== HELPERS ====================
def current_time():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def is_relevant_file(path):
    ext = os.path.splitext(path)[1].lower()
    if ext in IGNORED_EXTENSIONS:
        return False
    if any(keyword.lower() in path.lower() for keyword in IGNORED_KEYWORDS):
        return False
    return True

def persist_log(log):
    try:
        with open(LOG_FILE, "a") as f:
            f.write(str(log) + "\n")
    except Exception:
        pass

def detect_burst():
    now = time.time()
    EVENT_BURST_WINDOW.append(now)
    if len(EVENT_BURST_WINDOW) >= 15 and (now - EVENT_BURST_WINDOW[0]) < 10:
        anomaly_log = {
            "timestamp": current_time(),
            "user": getpass.getuser(),
            "type": "Anomaly Detected",
            "message": "High volume of events in short time window",
            "score": THREAT_SCORES["Anomaly Detected"]
        }
        EVENT_BUFFER.append(anomaly_log)
        CRITICAL_EVENTS.append(anomaly_log)
        persist_log(anomaly_log)

def add_event(event_type, message):
    user = getpass.getuser()
    score = THREAT_SCORES.get(event_type, 1)
    log = {
        "timestamp": current_time(),
        "user": user,
        "type": event_type,
        "message": message,
        "score": score
    }
    EVENT_BUFFER.append(log)
    persist_log(log)
    if score >= 7:
        CRITICAL_EVENTS.append(log)
    detect_burst()

# ==================== FILE MONITOR ====================
class FileIntegrityCollector(FileSystemEventHandler):
    def on_deleted(self, event):
        if not event.is_directory and is_relevant_file(event.src_path):
            add_event("File Deleted", f"Deleted: {event.src_path}")

    def on_created(self, event):
        if not event.is_directory and is_relevant_file(event.src_path):
            add_event("File Created", f"Created: {event.src_path}")

    def on_modified(self, event):
        if not event.is_directory and is_relevant_file(event.src_path):
            add_event("File Modified", f"Modified: {event.src_path}")

def start_file_monitor():
    observer = Observer()
    observer.schedule(FileIntegrityCollector(), MONITORED_DIR, recursive=True)
    observer.start()
    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

# ==================== PROCESS MONITOR ====================
def get_process_command(proc):
    try:
        return " ".join(proc.cmdline())
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return "N/A"
    except Exception:
        return ""

def process_telemetry_collector():
    while True:
        try:
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cmdline']):
                if proc.info['pid'] not in SEEN_PIDS:
                    ctime = datetime.fromtimestamp(proc.info['create_time'])
                    if ctime >= START_TIME:
                        SEEN_PIDS.add(proc.info['pid'])
                        proc_name = proc.info['name']
                        command = get_process_command(proc)

                        if 'cmd' in proc_name.lower() or 'powershell' in proc_name.lower():
                            add_event("CMD Opened", f"PID {proc.info['pid']} - Command: {command}")
                        else:
                            add_event("Process Started", f"Name: {proc_name} | PID: {proc.info['pid']} | Command: {command}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        time.sleep(1)

# ==================== DASHBOARD ====================
app = Dash(__name__)
app.title = "Host Security Monitor"

card_style = {
    'backgroundColor': '#1E1E1E',
    'border': '1px solid #3A3A3A',
    'borderRadius': '8px',
    'padding': '20px',
    'boxShadow': '0 4px 8px rgba(0,0,0,0.3)',
}

app.layout = html.Div(style={'backgroundColor': "#121212", 'color': '#E0E0E0', 'fontFamily': 'Roboto, sans-serif', 'padding': '30px'},
    children=[
        html.H1("Host Security & Activity Monitor", style={'textAlign': 'center', 'marginBottom': '30px'}),
        html.Div(style={'display': 'flex', 'gap': '20px', 'marginBottom': '40px'},
            children=[
                html.Div([html.H3("Uptime"), html.P(id='kpi-uptime', style={'fontSize': '24px', 'fontWeight': 'bold'})], style={**card_style, 'flex': 1, 'textAlign': 'center'}),
                html.Div([html.H3("Total Events"), html.P(id='kpi-total-events', style={'fontSize': '24px', 'fontWeight': 'bold'})], style={**card_style, 'flex': 1, 'textAlign': 'center'}),
                html.Div([html.H3("Critical Events"), html.P(id='kpi-critical-events', style={'fontSize': '24px', 'fontWeight': 'bold'})], style={**card_style, 'flex': 1, 'textAlign': 'center'})
            ]),
        html.Div(style={'display': 'flex', 'gap': '20px', 'marginBottom': '40px'},
            children=[
                html.Div([html.H2("Events Over Time"), dcc.Graph(id='timeline-chart', style={'height': '300px'})], style={**card_style, 'flex': 2}),
                html.Div([html.H2("Event Type Breakdown"), dcc.Graph(id='pie-chart', style={'height': '300px'})], style={**card_style, 'flex': 1})
            ]),
        html.Div(style={'display': 'flex', 'gap': '20px'},
            children=[
                html.Div([html.H2("🚨 Critical Alerts"), html.Div(id='critical-output', style={'whiteSpace': 'pre-wrap', 'height': '200px', 'overflowY': 'auto', 'border': '1px solid #F44336', 'padding': '10px', 'borderRadius': '5px', 'backgroundColor': '#111111'})], style={**card_style, 'flex': 1}),
                html.Div([html.H2("📜 All Events"), html.Div(id='event-output', style={'whiteSpace': 'pre-wrap', 'height': '300px', 'overflowY': 'auto', 'border': '1px solid #2196F3', 'padding': '10px', 'borderRadius': '5px', 'backgroundColor': '#111111'})], style={**card_style, 'flex': 2})
            ]),
        dcc.Interval(id='interval', interval=1000, n_intervals=0)
    ])

@app.callback(
    Output('kpi-uptime', 'children'),
    Output('kpi-total-events', 'children'),
    Output('kpi-critical-events', 'children'),
    Output('timeline-chart', 'figure'),
    Output('pie-chart', 'figure'),
    Output('critical-output', 'children'),
    Output('event-output', 'children'),
    Input('interval', 'n_intervals')
)
def update_dashboard(n):
    uptime_seconds = (datetime.now() - START_TIME).total_seconds()
    uptime_display = f"{int(uptime_seconds//3600)}h {int((uptime_seconds%3600)//60)}m {int(uptime_seconds%60)}s"
    total_events_display = str(len(EVENT_BUFFER))
    critical_events_display = str(len(CRITICAL_EVENTS))

    df = pd.DataFrame(list(EVENT_BUFFER))
    timeline_fig = {}
    pie_fig = {}

    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['count'] = 1
        timeline_data = df.resample('1s', on='timestamp').count().reset_index()
        timeline_fig = px.line(timeline_data, x='timestamp', y='count', labels={'timestamp':'Time','count':'Events'}, template='plotly_dark')
        timeline_fig.update_traces(line_color='#2196F3')
        pie_fig = px.pie(df, names='type', title='Event Type Breakdown', color_discrete_sequence=px.colors.sequential.deep, template='plotly_dark')

    critical_display = "\n".join([f"[{a['timestamp']}] {a['type']} ({a['user']}) - {a['message']}" for a in reversed(list(CRITICAL_EVENTS))]) or "No critical events yet."
    event_display = "\n".join([f"[{l['timestamp']}] {l['type']} ({l['user']}) - {l['message']}" for l in reversed(list(EVENT_BUFFER))]) or "No events yet."

    return uptime_display, total_events_display, critical_events_display, timeline_fig, pie_fig, critical_display, event_display

# ==================== MAIN ====================
if __name__ == "__main__":
    print(f"✅ Host Security Monitor started at {current_time()}")
    file_thread = threading.Thread(target=start_file_monitor, daemon=True)
    process_thread = threading.Thread(target=process_telemetry_collector, daemon=True)
    file_thread.start()
    process_thread.start()
    app.run(debug=False, port=8050)