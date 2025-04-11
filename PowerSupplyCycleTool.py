import socket
import tkinter as tk
from tkinter import BooleanVar, IntVar, ttk, scrolledtext
import threading
import time
import datetime
import queue
import subprocess
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
import requests
import csv
import os
import sys
import json
from ipaddress import IPv4Address, ip_address
from ordered_set import OrderedSet
import io
import git
from paramiko import AuthenticationException, BadHostKeyException, SSHClient, SSHException
from concurrent.futures import Future, ThreadPoolExecutor
import re

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TestBenchConnectionConfig:
    psu_address: IPv4Address

    def __init__(self, psu_address: IPv4Address):
        self.psu_address = psu_address
    
    def as_dict(self)->dict:
        return {
            "psu_address": str(self.psu_address)
        }

class TestBenchSSHConfig:
    username: str
    password: str
    command: str
    enabled: bool

    def __init__(self, username: str, password: str, command: str, enabled: bool):
        self.username = username
        self.password = password
        self.command = command
        self.enabled = enabled
    
    def as_dict(self)->dict:
        return {
            "username": str(self.username),
            "password": str(self.password),
            "command": str(self.command),
            "enabled": str(self.enabled),
        }

class TestBenchTimingConfig:
    pre_check_delay: float
    loop_check_period: float
    poweroff_delay: float
    max_startup_delay: float
    cycle_start: int

    def __init__(self, pre_check_delay: float, loop_check_period: float, poweroff_delay: float, max_startup_delay: float, cycle_start: int):
        self.pre_check_delay = pre_check_delay
        self.loop_check_period = loop_check_period
        self.poweroff_delay = poweroff_delay
        self.max_startup_delay = max_startup_delay
        self.cycle_start = cycle_start
    
    def as_dict(self)->dict:
        return {
            "pre_check_delay": self.pre_check_delay,
            "loop_check_period": self.loop_check_period,
            "poweroff_delay": self.poweroff_delay,
            "max_startup_delay": self.max_startup_delay,
            "cycle_start": self.cycle_start
        }


class TestBenchConfig:
    connection: TestBenchConnectionConfig
    timing: TestBenchTimingConfig
    ssh: TestBenchSSHConfig

    def __init__(self, connection: TestBenchConnectionConfig, timing: TestBenchTimingConfig, ssh: TestBenchSSHConfig):
        self.connection = connection
        self.timing = timing
        self.ssh = ssh
    
    @staticmethod
    def from_json(file_path: str):
        data = config_from_json(file_path)
        
        connection = data["connection"]
        psu_address = ip_address(connection["psu_address"])
        connection = TestBenchConnectionConfig(psu_address)

        timing = data["timing"]
        pre_check_delay = float(timing["pre_check_delay"])
        loop_check_period = float(timing["loop_check_period"])
        poweroff_delay = float(timing["poweroff_delay"])
        max_startup_delay = float(timing["max_startup_delay"])
        cycle_start = int(timing["cycle_start"])
    
        timing = TestBenchTimingConfig(pre_check_delay, loop_check_period, poweroff_delay, max_startup_delay, cycle_start)\
            
        ssh = data["ssh"]
        username = ssh["username"]
        password = ssh["password"]
        command = ssh["command"]
        # it sucks but it's convenient
        enabled = ssh["enabled"] == "True"
        
        ssh = TestBenchSSHConfig(username, password, command, enabled)

        return TestBenchConfig(connection, timing, ssh)

    def as_dict(self) -> dict:
        return {
            "connection": self.connection.as_dict(),
            "timing": self.timing.as_dict(),
            "ssh": self.ssh.as_dict()
        }

# Sostituisci con la tua implementazione o libreria effettiva per l'alimentatore Rigol.
from dp832 import dp832

def ip_from_url(url: str) -> (IPv4Address | None):
    ip = None
    ip_regex = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    ip_match = re.search(ip_regex, url)
    if ip_match is not None:
        ip = ip_match.group(0)
        ip = IPv4Address(ip)
    
    return ip

def get_current_git_commit_hash():
    repo = git.Repo(os.getcwd())
    sha = repo.head.object.hexsha
    return sha

def config_from_json(file_path: str):
    data = {}
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data

def url_list_from_csv(content: str) -> OrderedSet[str]:
    csv_file = io.StringIO(content)
    csv_reader = csv.DictReader(csv_file, delimiter=';')
    data = OrderedSet([row['url'] for row in csv_reader])
    return data

def run_ssh_command(server: IPv4Address, username: str, password: str, command: str) -> tuple:
    ssh = SSHClient()
    ssh.connect(str(server), username=username, password=password)
    return ssh.exec_command(command)

# check if a given url returns HTTP code 200 (success) using curl
# throws subprocess.TimeoutExpired or a generic exception
def curl(url: str) -> (datetime.datetime | None):
    result = subprocess.run(
        ['curl', '-k', '-s', '-o', '/dev/null', '-w', '%{http_code}', url],
        timeout=3,
        capture_output=True,
        text=True
    )
    timestamp = None
    if result.stdout.strip() == '200':
        timestamp = datetime.datetime.now()
    
    return timestamp

# returns an dict where the key is an URL (string) and the value is its completed future
# this way we can handle the future result outside of this function
def broadcast_ping(url_list: set[str]) -> dict[str, Future[datetime.datetime | None]]:
    # spawn a bunch of workers to start the pinging process
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        # run a different thread for each URL to ping and
        # create a dictionary where the future is the key and the URL is the value
        future_to_ip = {executor.submit(curl, url): url for url in url_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

# returns a dict where the key is the IP and the value is its completed future
def broadcast_ssh_command(ip_list: set[IPv4Address], username: str, password: str, command: str) -> dict[IPv4Address, Future[tuple | None]]:
    # spawn a bunch of workers to start the pinging process
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        # run a different thread for each URL to ping and
        # create a dictionary where the future is the key and the URL is the value
        future_to_ip = {executor.submit(run_ssh_command, ip, username, password, command): ip for ip in ip_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

class RigolTestApp(tk.Tk):
    url_list_filename = 'urls.csv'
    config_filename = 'config.json'
    window_title = "Rigol Test GUI"
    window_w = 1280
    window_h = 800

    def __init__(self, version):
        super().__init__()
        self.geometry(f"{self.window_w}x{self.window_h}")
        self.title(f"{self.window_title} (commit {version})")
        
        config_path = os.path.join(os.getcwd(), self.config_filename)
        self.config = TestBenchConfig.from_json(config_path)
        
        self.alimentatore = dp832()
    
        # Lista IP e tempi di rilevamento
        self.urls: OrderedSet[str] = OrderedSet()
        self.detection_times: dict[str, datetime.datetime] = {}
        self.cycle_defectives: set[str] = set()
        self.t0: datetime.datetime | None = None
        
        # Code per log e comunicazioni verso la GUI
        self.log_queue = queue.Queue()
        self.gui_queue = queue.Queue()
        
        # Controllo del loop di test
        self.run_test = False
        self.test_thread = None
        self.test_start_time = None
        
        # Contatori
        self.cycle_count = 0
        self.anomaly_count = 0
        
        # File di report
        self.report_filename = None
        self.report_folder = "reports"
        self.report_filepath = None
        
        # Flag per capire se lo stop è stato manuale
        self.test_stopped_intentionally = False
        
        # Creazione interfaccia grafica
        self.create_widgets()
        
        # Gestione code
        self.after(500, self.process_log_queue)
        self.after(100, self.process_gui_queue)

        # TODO make this configurable from UI

    def create_widgets(self):
        """
        Crea tutti i widget (label, entry, treeview, pulsanti) e li posiziona nella finestra principale.
        """
        # Configurazione della griglia principale
        # self.grid_columnconfigure(0, weight=1)

        # self.grid_rowconfigure(0, weight=1)
        # self.grid_rowconfigure(1, weight=1)

        # TOP FRAME
        top_frame = tk.Frame(self)
        top_frame.grid(row=0, column=0, sticky="new")
        top_frame.grid_rowconfigure(0, weight=1)
        top_frame.grid_columnconfigure(0, weight=1)
        top_frame.grid_columnconfigure(1, weight=1)

        # TOP LEFT FRAME
        top_left_frame = tk.Frame(top_frame)
        top_left_frame.grid(row=0, column=0, sticky="nw")

        self.init_psu_frame(top_left_frame, 0, 0)
        self.init_params_frame(top_left_frame, 1, 0)
        self.init_ssh_frame(top_left_frame, 2, 0)
        
        # TOP RIGHT FRAME
        top_right_frame = tk.Frame(top_frame)
        top_right_frame.grid(row=0, column=1, sticky="ne")

        self.init_url_file_frame(top_right_frame, 0, 0)
        
        # BOTTOM FRAME
        bottom_frame = tk.Frame(self)
        bottom_frame.grid(row=1, column=0, sticky="new")
        bottom_frame.grid_rowconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(0, weight=1)
        bottom_frame.grid_columnconfigure(1, weight=1)

        # BOTTOM LEFT FRAME
        bottom_left_frame = tk.Frame(bottom_frame)
        bottom_left_frame.grid(row=0, column=0, sticky="nw")

        self.init_command_frame(bottom_left_frame, 0, 0)
        self.init_info_frame(bottom_left_frame, 1, 0)
        self.init_ip_table(bottom_left_frame, 2, 0)
        
        # BOTTOM RIGHT FRAME
        bottom_right_frame = tk.Frame(bottom_frame)
        bottom_right_frame.grid(row=0, column=1, sticky="ne")

        self.init_log_frame(bottom_right_frame, 0, 0)
        
    
    def init_url_file_frame(self, parent, row, col):
        self.url_file_frame = ttk.Frame(parent)
        self.url_file_frame.grid(row=row, column=col, padx=5, pady=5)

        self.url_file = scrolledtext.ScrolledText(self.url_file_frame)
        self.url_file.grid(row=0, column=0)
        self.url_file.config(height=15)

        url_list_path = os.path.join(os.getcwd(), self.url_list_filename)
        with open(url_list_path) as f: content = f.read()
        self.url_file.insert('1.0', content)

        self.apply_button = ttk.Button(self.url_file_frame, text="Apply", command=self.apply_url_file)
        self.apply_button.grid(row=1, column=0, padx=5, pady=5)
    
    def init_info_frame(self, parent, row, col):
        # Frame 3: Info frame (timer, contatori)
        info_frame = ttk.Frame(parent)
        info_frame.grid(row=row, column=col, padx=10, pady=5, sticky="nw")

        self.elapsed_time_label = ttk.Label(info_frame, text="Test non ancora partito.")
        self.elapsed_time_label.pack(side="left", padx=5)

        self.cycle_count_label = ttk.Label(info_frame, text="Accensioni eseguite: 0")
        self.cycle_count_label.pack(side="left", padx=5)

        self.anomaly_count_label = ttk.Label(info_frame, text="Accensioni con anomalia: 0")
        self.anomaly_count_label.pack(side="left", padx=5)
    
    def init_command_frame(self, parent, row, col):
        # Frame 4: Controlli manuali
        self.manual_frame = ttk.LabelFrame(parent, text="Controlli Manuali")
        self.manual_frame.grid(row=row, column=col, padx=5, pady=5, sticky="nw")

        # self.manual_frame.grid_columnconfigure(3, weight=1)

        self.start_button = ttk.Button(self.manual_frame, text="Start", command=self.start_test)
        self.start_button.pack(side="left", padx=5, pady=5)

        self.stop_button = ttk.Button(self.manual_frame, text="Stop", command=self.stop_test)
        self.stop_button.pack(side="left", padx=5, pady=5)

        self.pause_button = ttk.Button(self.manual_frame, text="Pausa", command=self.toggle_pause)
        self.pause_button.pack(side="left", padx=5, pady=5)

        self.force_on_button = ttk.Button(self.manual_frame, text="Forza ON", command=self.force_power_on)
        self.force_on_button.pack(side="left", padx=5, pady=5)

        self.force_off_button = ttk.Button(self.manual_frame, text="Forza OFF", command=self.force_power_off)
        self.force_off_button.pack(side="left", padx=5, pady=5)

        self.pause_status_label = ttk.Label(self.manual_frame, text="Stato: In esecuzione")
        self.pause_status_label.pack(side="left", padx=5, pady=5)
    
    def init_params_frame(self, parent, row, col):
        # Frame 2: Configurazione Tempi
        self.times_frame = ttk.LabelFrame(parent, text="Configurazione Tempi (in secondi)")
        self.times_frame.grid(row=row, column=col, padx=10, pady=5, sticky="nw")

        labels_entries = [
            ("Attesa prima di controllare IP (Pre-check):", "entry_precheck", self.config.timing.pre_check_delay),
            ("Intervallo tra controlli IP:", "entry_checkloop", self.config.timing.loop_check_period),
            ("Durata spegnimento:", "entry_speg", self.config.timing.poweroff_delay),
            ("Massimo ritardo avvio dispositivi:", "entry_maxdelay", self.config.timing.max_startup_delay),
            ("Conteggio di partenza:", "entry_cycle_start", self.config.timing.cycle_start)
        ]

        for idx, (label_text, entry_name, default_value) in enumerate(labels_entries):
            ttk.Label(self.times_frame, text=label_text).grid(row=idx, column=0, sticky="w", padx=5, pady=2)
            entry_var = tk.StringVar()
            entry_var.set(default_value)
            callback_name = f"on_{entry_name}_change"
            callback = getattr(self, callback_name)
            entry_var.trace_add("write", callback)

            setattr(self, f"{entry_name}_var", entry_var)
            entry = ttk.Entry(self.times_frame, width=6, textvariable=entry_var)
            entry.grid(row=idx, column=1, sticky="w", padx=5, pady=2)
            setattr(self, entry_name, entry)
    
    def init_ssh_frame(self, parent, row, col):
        self.ssh_frame = ttk.LabelFrame(parent, text="SSH")
        self.ssh_frame.grid(row=row, column=col, padx=10, pady=5, sticky="nw")
        
        self.chkValue = IntVar(master = self.ssh_frame, value=self.config.ssh.enabled)
        
        c1 = tk.Checkbutton(self.ssh_frame, text='Run SSH command on power-off',variable=self.chkValue, command=self.on_checkbutton_toggle)
        c1.grid(row=row, column=col, padx=10, pady=5, sticky="nw")
        
        ttk.Label(self.ssh_frame, text="Username").grid(row=row+1, column=col, sticky="w", padx=5, pady=2)
        self.username_var = tk.StringVar()
        self.username_var.set(self.config.ssh.username)
        self.username_var.trace_add("write", self.on_username_change)
        username = ttk.Entry(self.ssh_frame, width=20, textvariable=self.username_var)
        username.grid(row=row+1, column=col+1, padx=10, pady=5, sticky="nw")
        
        ttk.Label(self.ssh_frame, text="Password").grid(row=row+2, column=col, sticky="w", padx=5, pady=2)
        self.password_var = tk.StringVar()
        self.password_var.set(self.config.ssh.password)
        self.password_var.trace_add("write", self.on_password_change)
        password = ttk.Entry(self.ssh_frame, width=20, textvariable=self.password_var)
        password.grid(row=row+2, column=col+1, padx=10, pady=5, sticky="nw")
        
        ttk.Label(self.ssh_frame, text="Command").grid(row=row+3, column=col, sticky="w", padx=5, pady=2)
        self.command_var = tk.StringVar()
        self.command_var.set(self.config.ssh.command)
        command = ttk.Entry(self.ssh_frame, width=20, textvariable=self.command_var)
        self.command_var.trace_add("write", self.on_command_change)
        command.grid(row=row+3, column=col+1, padx=10, pady=5, sticky="nw")
    
    def on_checkbutton_toggle(self, *args):
        self.config.ssh.enabled = not self.config.ssh.enabled
        self.save_config()
    
    def on_username_change(self, *args):
        self.config.ssh.username = self.username_var.get()
        self.save_config()
    
    def on_password_change(self, *args):
        self.config.ssh.password = self.password_var.get()
        self.save_config()
    
    def on_command_change(self, *args):
        self.config.ssh.command = self.command_var.get()
        self.save_config()
    
    # TODO each _var is created inside the loop right above here. Please declare them as class properties
    def on_entry_precheck_change(self, *args):
        if hasattr(self, "entry_precheck_var"):
            try:
                value = float(self.entry_precheck_var.get())
                self.config.timing.pre_check_delay = value
                self.save_config()
            except:
                pass
    
    def on_entry_checkloop_change(self, *args):
        if hasattr(self, "entry_checkloop_var"):
            try:
                value = float(self.entry_checkloop_var.get())
                self.config.timing.loop_check_period = value
                self.save_config()
            except:
                pass

    def on_entry_speg_change(self, *args):
        if hasattr(self, "entry_speg_var"):
            try:
                value = float(self.entry_speg_var.get())
                self.config.timing.poweroff_delay = value
                self.save_config()
            except:
                pass
    
    def on_entry_cycle_start_change(self, *args):
        if hasattr(self, "entry_cycle_start_var"):
            try:
                value = int(self.entry_cycle_start_var.get())
                self.config.timing.cycle_start = value
                self.save_config()
            except:
                pass
    
    def on_entry_maxdelay_change(self, *args):
        if hasattr(self, "entry_maxdelay_var"):
            try:
                value = float(self.entry_maxdelay_var.get())
                self.config.timing.max_startup_delay = value
                self.save_config()
            except:
                pass
    
    def save_config(self):
        config_path = os.path.join(os.getcwd(), self.config_filename)
        data = self.config.as_dict()
        data_json = json.dumps(data)
        with open(config_path, mode="w", encoding="utf-8") as file:
            file.write(data_json)
    
    def init_psu_frame(self, parent, row, col):
        # Frame 1: IP Alimentatore, Range IP e URL di verifica
        self.range_frame = ttk.LabelFrame(parent, text="Alimentatore")
        self.range_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")

        # self.range_frame.grid_columnconfigure(6, weight=1)

        # Riga 0: IP Alimentatore, IP Start e IP End
        ttk.Label(self.range_frame, text="IP Alimentatore:").grid(row=0, column=0, padx=5, pady=5)
        self.dp832_entry = ttk.Entry(self.range_frame, width=15)
        self.dp832_entry.insert(0, str(self.config.connection.psu_address))
        self.dp832_entry.grid(row=0, column=1, padx=5)
    
    def init_ip_table(self, parent, row, col):
        # Frame 5: Tabella IP
        self.table_frame = ttk.Frame(parent)
        self.table_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")

        ttk.Label(self.table_frame, text="Stato IP (Mostra orario di rilevamento):").pack(anchor="w")

        columns = ("ip", "detected")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        self.tree.heading("ip", text="Indirizzo IP")
        self.tree.heading("detected", text="Rilevato alle (HH:MM:SS)")
        self.tree.column("ip", width=200)
        self.tree.column("detected", width=300)

        # Definizione dei tag per la Treeview
        self.tree.tag_configure('error', foreground='red')
        self.tree.tag_configure('normal', foreground='black')

        # Set fixed height (for example, 10 rows max visible)
        self.tree.config(height=10)

        # Pack Treeview with fill='y' so it adjusts to the height
        self.tree.pack(side='left', fill='both', expand=True)

        # Scrollbar
        vsb = ttk.Scrollbar(self.table_frame, orient="vertical", command=self.tree.yview)
        vsb.pack(side='right', fill='y')

        self.tree.configure(yscrollcommand=vsb.set)
    
    def init_log_frame(self, parent, row, col):
        # Frame 6: Controlli e Log
        self.controls_frame = ttk.LabelFrame(parent, text="Log")
        self.controls_frame.grid(row=row, column=col, padx=10, pady=5, sticky="nsew")

        # Area Log
        # ttk.LabelFrame(self.controls_frame, text="Log").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(self.controls_frame, wrap=tk.WORD)
        self.log_text.grid(row=2, column=0, sticky="nsew")
        self.log_text.config(height=17)

    
    def apply_url_file(self):
        content = self.url_file.get("1.0", "end-1c")
        self.urls = url_list_from_csv(content)
        self.refresh_address_table()
        
        url_list_path = os.path.join(os.getcwd(), self.url_list_filename)
        with open(url_list_path, mode="w", encoding="utf-8") as file:
            file.write(content)
            
    def clear_address_table(self):
        self.urls.clear()
        self.refresh_address_table()
    
    def refresh_address_table(self):
        # Pulisce la Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Resetta i tempi di rilevamento
        self.detection_times.clear()
        for ip in self.urls:
            self.detection_times[ip] = None
            self.tree.insert("", tk.END, iid=ip, values=(ip, ""), tags=('normal',))
            self.log(f"[INFO] URL found: {ip}")
        
    def log(self, message):
        """Aggiunge un messaggio alla coda di log."""
        self.log_queue.put(message)

    def process_log_queue(self):
        """Aggiorna l'area log con i messaggi in coda."""
        while True:
            try:
                msg = self.log_queue.get_nowait()
            except queue.Empty:
                break
            else:
                self.log_text.insert(tk.END, msg + "\n")
                self.log_text.see(tk.END)
        self.after(500, self.process_log_queue)

    def process_gui_queue(self):
        """Gestisce gli aggiornamenti della GUI dalla coda."""
        while True:
            try:
                gui_msg = self.gui_queue.get_nowait()
                if gui_msg[0] == 'update_label':
                    _, label_name, text = gui_msg
                    getattr(self, label_name).config(text=text)
                elif gui_msg[0] == 'update_tree':
                    ip, detected_time = gui_msg[1], gui_msg[2]
                    self.tree.set(ip, "detected", detected_time)
                elif gui_msg[0] == 'highlight_error':
                    ip = gui_msg[1]
                    self.tree.item(ip, tags=('error',))
                elif gui_msg[0] == 'remove_tag':
                    ip = gui_msg[1]
                    self.tree.item(ip, tags=('normal',))
            except queue.Empty:
                break
            except Exception as e:
                self.log(f"[ERRORE] Errore in process_gui_queue: {str(e)}")
        self.after(100, self.process_gui_queue)

    def make_report_filename(self):
        """Genera un nome file per il report basato sulla data e ora corrente."""
        now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"report_{now_str}.csv"
        return filename

    def write_test_start_line(self):
        """Scrive una riga di intestazione nel file di report per l'inizio del test."""
        if not self.report_filepath:
            self.log("[ERRORE] Nome del file di report non definito.")
            return
        start_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"### Test started at {start_time_str}\n"
        try:
            with open(self.report_filepath, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            self.log(f"[ERRORE] Errore durante la scrittura del file di report: {str(e)}")
    
    def ping_with_detection_time(self, url_list: list[str]) -> dict[str, (datetime.datetime | None)]:
        detection_times: dict[str, (datetime.datetime | None)] = dict()
        url_futures = broadcast_ping(url_list)
        
        response = None
        
        for url,future in url_futures.items():
            try:
                response = future.result()
            except subprocess.TimeoutExpired:
                response = None
                self.log(f"[ERRORE] {url} non ha risposto al ping")
            except Exception as exc:
                response = None
                self.log(f"[ERRORE] Verifica IP {url} ha generato un'eccezione: {exc}")
        
            detection_times[url] = response
        
        return detection_times
    
    # returns True every url of the urls list has answered, otherwise it returns False
    def ping(self) -> bool:
        # ping only the URLs that havent' answered yet and save their detection times
        url_list_to_ping = set([url for url in self.urls if self.detection_times[url] is None])
        detection_times = self.ping_with_detection_time(url_list_to_ping)
        # remove the None responses
        detection_times_valid = {k: v for k,v in detection_times.items() if v is not None}
        # if the reference time haven't been already set, check if it can be set
        if self.t0 is None and len(detection_times_valid) != 0:
            self.t0 = min([v for v in detection_times_valid.values()])
        
        # here we enter only if detection_times_valid is not empty, so t0 have been already set
        # here we compute the time difference between the first response (reference t0) and the other URLs
        for url,detection_time in detection_times_valid.items():
            self.detection_times[url] = detection_time
            detected_time_str = self.detection_times[url].strftime("%H:%M:%S.%f")[:-3]
            self.gui_queue.put(('update_tree', url, detected_time_str))
            self.log(f"[INFO] IP {url} rilevato alle {detected_time_str}")
            elapsed_since_t0 = (self.detection_times[url] - self.t0).total_seconds()
            # if the time difference is greater than the max startup delay, flag it as anomaly
            if elapsed_since_t0 > self.config.timing.max_startup_delay and url not in self.cycle_defectives:
                self.log(f"[ALLARME] IP {url} rilevato con ritardo di {elapsed_since_t0:.3f} secondi.")
                self.cycle_defectives.add(url)
        
        # if every URL has answered, generate the report file and exit
        if all(self.detection_times[ip] is not None for ip in self.urls):
            detection_sorted = sorted(self.detection_times.items(), key=lambda x: x[1])
            ip_first, t_first = detection_sorted[0]
            ip_last, t_last = detection_sorted[-1]
            delay = (t_last - t_first).total_seconds()
            self.save_cycle_report(ip_first, ip_last, delay)
            return True
        
        # finally check who didn't responded yet
        non_rilevati = [ip for ip in self.urls if self.detection_times[ip] is None]
        for ip in non_rilevati:
            self.log(f"[ALLARME] IP {ip} non ha risposto entro {self.config.timing.max_startup_delay} secondi.")
            self.gui_queue.put(('highlight_error', ip))
            self.cycle_defectives.add(ip)
        
        return False
    
    def psu_connect(self):
        self.alimentatore.connect(self.config.connection.psu_address)        
    
    def psu_init(self):
        self.alimentatore.set_voltage(1, 26.000)
        self.alimentatore.set_voltage(2, 26.000)
    
    def psu_poweroff(self):
        self.psu_set_state('OFF')
    
    def psu_poweron(self):
        self.psu_set_state('ON')
    
    def psu_set_state(self, state: str):
        for channel in (1, 2):
            self.alimentatore.select_output(channel)
            self.alimentatore.toggle_output(channel, state)
    
    def test_loop(self):
        """
        Loop principale di test:
        - Accende l'alimentatore.
        - Verifica in parallelo la risposta degli IP tramite ip_responds_curl.
        - Utilizza la stringa configurabile per costruire l'URL di verifica.
        """
        
        # connect to the PSU
        self.log(f"[INFO] Connessione all'alimentatore {self.config.connection.psu_address}...")
        try:
            self.psu_connect()
            self.psu_init()
        except Exception as e:
            self.log(f"[ERRORE] Impossibile connettersi all'alimentatore: {str(e)}")
            self.run_test = False
            return
        
        # start the main loop
        while self.wait_with_stop_check(self.config.timing.loop_check_period):
            # Gestione pausa
            if self.is_paused:
                continue
            
            self.cycle_defectives.clear()
            self.t0 = None
            self.cycle_count += 1
            self.gui_queue.put(('update_label', 'cycle_count_label', f"Accensioni eseguite: {self.cycle_count}"))
            
            self.log(f"[INFO] (Ciclo {self.cycle_count}) Accendo alimentatore (canali 1 e 2)...")
            try:
                self.psu_poweron()
            except Exception as e:
                self.log(f"[ERRORE] Errore durante l'accensione: {str(e)}")
                continue
            
            # clear detection times and GUI
            for ip in self.urls:
                self.detection_times[ip] = None
                self.gui_queue.put(('update_tree', ip, ""))
                self.gui_queue.put(('remove_tag', ip))
            
            # wait for precheck delay
            self.log(f"[INFO] Attendo {self.config.timing.pre_check_delay} secondi prima del controllo degli IP.")
            if not self.wait_with_stop_check(self.config.timing.pre_check_delay):
                break
            
            # start the pinging loop
            # it exits if the ping is successfull (every URL has answered)
            self.log(f"[INFO] Inizio controllo rapido degli IP ogni {self.config.timing.loop_check_period}s.")
            while self.wait_with_stop_check(self.config.timing.loop_check_period):
                if self.is_paused:
                    continue
                if self.ping():
                    break
            
            # update the anomaly count using the size of the cycle_defectives set
            self.anomaly_count = self.anomaly_count + len(self.cycle_defectives)
            self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
            
            if self.config.ssh.enabled:
                self.log("[INFO] Tutti gli IP hanno risposto. Attendo 5 secondi prima di lanciare il comando via SSH")
                if not self.wait_with_stop_check(5):
                    break
                ip_list = [ip_from_url(url) for url in self.urls]
                ip_list = [ip for ip in ip_list if ip is not None]
                futures_dict = broadcast_ssh_command(ip_list, self.config.ssh.username, self.config.ssh.password, self.config.ssh.command)
                for ip,future in futures_dict.items():
                    try:
                        stdint, stdout, stderr = future.result()
                        self.log(f"[INFO] SSH command succesfully sent to {str(ip)}")
                    except BadHostKeyException as e:
                        self.log(f"[ERROR] Bad host key: {e}")
                    except AuthenticationException as e:
                        self.log(f"[ERROR] Authentication exception: {e}")
                    except socket.error as e:
                        self.log(f"[ERROR] socket error: {e}")
                    except SSHException as e:
                        self.log(f"[ERROR] SSH exception: {e}")
                    except Exception as e:
                        self.log(f"[ERROR] Generic error: {e}")
            
            else:    
                self.log("[INFO] Tutti gli IP hanno risposto. Attendo 5 secondi prima di spegnere l'alimentatore.")
                if not self.wait_with_stop_check(5):
                    break

                self.log("[INFO] Spengo alimentatore (canali 1 e 2)...")
                try:
                    self.psu_poweroff()
                    self.log(f"[INFO] Attendo {self.config.timing.poweroff_delay} secondi durante lo spegnimento...")
                    if not self.wait_with_stop_check(self.config.timing.poweroff_delay):
                        break
                except Exception as e:
                    self.log(f"[ERRORE] Errore durante lo spegnimento: {str(e)}")
                    continue

        if not self.test_stopped_intentionally:
            self.log("[INFO] Spegnimento finale dell'alimentatore...")
            try:
                self.psu_poweroff()
                self.log(f"[INFO] Attendo {self.config.timing.poweroff_delay} secondi durante lo spegnimento finale...")
                time.sleep(self.config.timing.poweroff_delay)
            except Exception as e:
                self.log(f"[ERRORE] Errore durante lo spegnimento finale: {str(e)}")
        
        self.log("[INFO] Test terminato.")

    def save_cycle_report(self, ip_first, ip_last, delay):
        """
        Salva nel report:
        - Data/ora
        - Numero del ciclo
        - IP del primo e dell'ultimo dispositivo che hanno risposto
        - Ritardo tra il primo e l'ultimo
        """
        if not self.report_filepath:
            self.log("[ERRORE] Nome del file di report non definito. Impossibile salvare il ciclo.")
            return
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cycle_str = f"{self.cycle_count:5d}"
        line = f"{now_str};\t{cycle_str};\t{ip_first};\t{ip_last};\t{delay:.3f}\n"
        try:
            with open(self.report_filepath, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            self.log(f"[ERRORE] Errore durante la scrittura del ciclo nel report: {str(e)}")

    def start_test(self):
        """Avvia il test in un thread separato, reimpostando contatori e flag."""
        if not self.run_test:
            self.run_test = True
            self.is_paused = False
            self.pause_status_label.configure(text="Stato: In esecuzione")
            self.pause_button.configure(text="Pausa")
            self.log("[INFO] Test avviato.")
            self.test_start_time = time.time()
            self.update_elapsed_time()
            self.test_stopped_intentionally = False
            self.cycle_count = self.config.timing.cycle_start
            self.gui_queue.put(('update_label', 'cycle_count_label', f"Accensioni eseguite: {self.cycle_count}"))
            self.anomaly_count = 0
            self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
            self.report_filename = self.make_report_filename()
            report_folderpath = os.path.join(os.getcwd(), self.report_folder)
            os.makedirs(report_folderpath, exist_ok=True)
            self.report_filepath = os.path.join(report_folderpath, self.report_filename)
            if self.report_filepath:
                self.write_test_start_line()
            else:
                self.log("[ERRORE] Non è stato possibile creare il file di report. Il test continuerà senza logging.")
            self.test_thread = threading.Thread(target=self.test_loop, daemon=True)
            self.test_thread.start()

    def stop_test(self):
        """Ferma il test in modo pulito."""
        self.run_test = False
        self.test_stopped_intentionally = True
        self.log("[INFO] Richiesto stop del test.")

    def update_elapsed_time(self):
        """Aggiorna il timer dell'interfaccia."""
        if self.run_test and self.test_start_time is not None:
            elapsed = time.time() - self.test_start_time
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            self.elapsed_time_label.config(text=f"Tempo dall'avvio: {elapsed_str}")
            self.after(1000, self.update_elapsed_time)

    def toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.pause_button.configure(text="Riprendi")
            self.pause_status_label.configure(text="Stato: In Pausa")
            self.log("[INFO] Test in pausa.")
        else:
            self.pause_button.configure(text="Pausa")
            self.pause_status_label.configure(text="Stato: In esecuzione")
            self.log("[INFO] Test ripreso.")

    def force_power_on(self):
        """Forza manualmente l'accensione dell'alimentatore."""
        try:
            self.log(f"[INFO] Connessione all'alimentatore {self.config.connection.psu_address}...")
            self.psu_connect()
            self.psu_init()
            self.psu_poweron()
            self.log("[INFO] Alimentatore forzato su ON.")
        except Exception as e:
            self.log(f"[ERRORE] Errore durante l'accensione forzata: {str(e)}")

    def force_power_off(self):
        """Forza manualmente lo spegnimento dell'alimentatore."""
        try:
            self.log(f"[INFO] Connessione all'alimentatore {self.config.connection.psu_address}...")
            self.psu_connect()
            self.psu_poweroff()
            self.log("[INFO] Alimentatore forzato su OFF.")
        except Exception as e:
            self.log(f"[ERRORE] Errore durante lo spegnimento forzato: {str(e)}")

    def wait_with_stop_check(self, seconds):
        """Esegue attese a piccoli step verificando se il test è ancora attivo."""
        steps = int(seconds / self.config.timing.loop_check_period)
        for _ in range(steps):
            if not self.run_test:
                return False
            time.sleep(self.config.timing.loop_check_period)
        return True

# Avvio dell'applicazione
if __name__ == "__main__":
    version =  get_current_git_commit_hash()
    app = RigolTestApp(version)
    app.mainloop()
