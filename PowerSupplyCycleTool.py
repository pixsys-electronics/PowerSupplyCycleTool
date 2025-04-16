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
from paramiko import AuthenticationException, AutoAddPolicy, BadHostKeyException, SSHClient, SSHException
from concurrent.futures import Future, ThreadPoolExecutor
import re
from pyModbusTCP.client import ModbusClient
from config import TestBenchConfig
from gui import FileFrame, InfoFrame, IpTableFrame, LogFrame, ManualControlsFrame, ModbusFrame, PsuFrame, SSHFrame, TimingFrame

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class Debouncer:
    def __init__(self, tk_root, delay_ms, callback):
        self.root = tk_root
        self.delay = delay_ms
        self.callback = callback
        self._job = None

    def call(self, *args, **kwargs):
        if self._job is not None:
            self.root.after_cancel(self._job)
        self._job = self.root.after(self.delay, lambda: self.callback(*args, **kwargs))


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

def url_list_from_csv(content: str) -> OrderedSet[str]:
    csv_file = io.StringIO(content)
    csv_reader = csv.DictReader(csv_file, delimiter=';')
    data = OrderedSet([row['url'] for row in csv_reader])
    return data

def run_ssh_command(server: IPv4Address, username: str, password: str, command: str) -> tuple:
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    ssh.connect(str(server), username=username, password=password)
    return ssh.exec_command(command)

def run_modbus_read_registers(host: IPv4Address, reg_addr: int, reg_num: int):
    c = ModbusClient(host=str(host), auto_open=True, auto_close=True)
    regs = c.read_holding_registers(reg_addr, reg_num)
    return regs

def run_modbus_write_regiter(host: IPv4Address, reg_addr: int, value: int):
    c = ModbusClient(host=str(host), auto_open=True, auto_close=True)
    ok = c.write_single_register(reg_addr, value)
    return ok

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

def broadcast_modbus_read_register(ip_list: set[IPv4Address], reg_addr: int, reg_num: int) -> dict[IPv4Address, Future[list | None]]:
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(run_modbus_read_registers, ip, reg_addr, reg_num): ip for ip in ip_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

def broadcast_modbus_write_register(ip_list: set[IPv4Address], reg_addr: int, reg_value: int) -> dict[IPv4Address, Future[bool]]:
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(run_modbus_write_regiter, ip, reg_addr, reg_value): ip for ip in ip_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

def broadcast_modbus_read_poweron_counter(ip_list) -> dict[IPv4Address, Future[list | None]]:
    return broadcast_modbus_read_register(ip_list, 0, 1)

def broadcast_modbus_write_poweron_counter(ip_list, reg_value: int) -> dict[IPv4Address, Future[bool]]:
    return broadcast_modbus_write_register(ip_list, 0, reg_value)

class RigolTestApp(tk.Tk):
    url_list_filename = 'urls.csv'
    config_filename = 'config.json'
    window_title = "Rigol Test GUI"
    window_w = 1280
    window_h = 800
    psu_frame: PsuFrame
    timing_frame: TimingFrame
    ssh_frame: SSHFrame
    modbus_frame: ModbusFrame
    file_frame: FileFrame
    manual_controls_frame: ManualControlsFrame
    info_frame: InfoFrame
    ip_frame: IpTableFrame
    log_frame: LogFrame
    save_config_debouncer: Debouncer

    def __init__(self, version):
        super().__init__()
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
        
        self.save_config_debouncer = Debouncer(self, 500, self.save_config)

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
        top_frame.grid(row=0, column=0, sticky="nsew")
        # top_frame.grid_rowconfigure(0, weight=1)
        # top_frame.grid_columnconfigure(0, weight=1)
        # top_frame.grid_columnconfigure(1, weight=1)

        # TOP LEFT FRAME
        top_left_frame = tk.Frame(top_frame)
        top_left_frame.grid(row=0, column=0, sticky="nsew")

        self.psu_frame = PsuFrame(top_left_frame, 0, 0, 5, 5, "nsew")
        self.psu_frame.set_psu_enabled(self.config.connection.psu_enabled)
        self.psu_frame.set_psu_ip(self.config.connection.psu_address)
        self.psu_frame.set_psu_enabled_change_cb(self.on_psu_enable_change)
        self.psu_frame.set_psu_ip_change_cb(self.on_psu_ip_change)
        
        self.timing_frame = TimingFrame(top_left_frame, 1, 0, 5, 5, "nsew")
        self.timing_frame.set_precheck(self.config.timing.pre_check_delay)
        self.timing_frame.set_checkloop(self.config.timing.loop_check_period)
        self.timing_frame.set_maxdelay(self.config.timing.max_startup_delay)
        self.timing_frame.set_speg(self.config.timing.poweroff_delay)
        self.timing_frame.set_cycle_start(self.config.timing.cycle_start)
        
        self.timing_frame.set_precheck_cb(self.on_timing_precheck_change)
        self.timing_frame.set_maxdelay_cb(self.on_timing_maxdelay_change)
        self.timing_frame.set_speg_cb(self.on_timing_speg_change)
        self.timing_frame.set_checkloop_cb(self.on_timing_checkloop_change)
        self.timing_frame.set_cycle_start_cb(self.on_timing_cycle_start_change)
        
        self.ssh_frame = SSHFrame(top_left_frame, 2, 0, 5, 5, "nsew")
        self.ssh_frame.set_ssh_enabled(self.config.ssh.enabled)
        self.ssh_frame.set_username(self.config.ssh.username)
        self.ssh_frame.set_password(self.config.ssh.password)
        self.ssh_frame.set_command(self.config.ssh.command)
        
        self.ssh_frame.set_ssh_enabled_change_cb(self.on_ssh_enabled_change)
        self.ssh_frame.set_username_change_cb(self.on_ssh_username_change)
        self.ssh_frame.set_password_change_cb(self.on_ssh_password_change)
        self.ssh_frame.set_command_change_cb(self.on_ssh_command_change)
        
        self.modbus_frame = ModbusFrame(top_left_frame, 3, 0, 5, 5, "nsew")
        self.modbus_frame.set_modbus_enable(self.config.modbus.automatic_cycle_count_check_enabled)
        self.modbus_frame.set_register_address(self.config.modbus.register_address)
        self.modbus_frame.set_register_value(self.config.modbus.register_value)
        
        self.modbus_frame.set_modbus_enable_change_cb(self.on_modbus_enable_change)
        self.modbus_frame.set_register_address_change_cb(self.on_modbus_register_address_change)
        self.modbus_frame.set_register_value_change_cb(self.on_modbus_register_value_change)
        self.modbus_frame.set_read_register_press_cb(self.on_modbus_read_press)
        self.modbus_frame.set_write_register_press_cb(self.on_modbus_write_press)
        self.modbus_frame.set_reset_cycle_count_press_cb(self.on_modbus_reset_cycle_count_press)
        self.modbus_frame.set_reset_time_count_press_cb(self.on_modbus_reset_time_count_press)
        
        # TOP RIGHT FRAME
        top_right_frame = tk.Frame(top_frame)
        top_right_frame.grid(row=0, column=1, sticky="nsew")
        
        self.log_frame = LogFrame(top_right_frame, 0, 0, 5, 5, "nsew")
        
        # BOTTOM FRAME
        bottom_frame = tk.Frame(self)
        bottom_frame.grid(row=1, column=0, sticky="nsew")
        # bottom_frame.grid_rowconfigure(0, weight=1)
        # bottom_frame.grid_columnconfigure(0, weight=1)
        # bottom_frame.grid_columnconfigure(1, weight=1)

        # BOTTOM LEFT FRAME
        bottom_left_frame = tk.Frame(bottom_frame)
        bottom_left_frame.grid(row=0, column=0, sticky="nsew")

        self.manual_controls_frame = ManualControlsFrame(bottom_left_frame, 0, 0, 5, 5, "nsew")
        self.manual_controls_frame.set_start_button_press_cb(self.on_commands_start_test)
        self.manual_controls_frame.set_stop_button_press_cb(self.on_commands_stop_test)
        self.manual_controls_frame.set_pause_button_press_cb(self.on_commands_toggle_pause)
        self.manual_controls_frame.set_force_on_button_press_cb(self.on_commands_force_power_on)
        self.manual_controls_frame.set_force_off_button_press_cb(self.on_commands_force_power_off)
        
        self.info_frame = InfoFrame(bottom_left_frame, 1, 0, 5, 5, "nsew")
        self.ip_frame = IpTableFrame(bottom_left_frame, 2, 0, 5, 5, "nsew")
        
        # BOTTOM RIGHT FRAME
        bottom_right_frame = tk.Frame(bottom_frame)
        bottom_right_frame.grid(row=0, column=1, sticky="nsew")
        
        self.file_frame = FileFrame(bottom_right_frame, 0, 0, 5, 5, "nsew")
        url_list_path = os.path.join(os.getcwd(), self.url_list_filename)
        with open(url_list_path) as f: content = f.read()
        self.file_frame.load_text(content)
        self.file_frame.set_apply_button_press_cb(self.on_file_apply_press)
        
        self.update()
        self.geometry("")
    
    def on_ssh_enabled_change(self, value: bool):
        self.config.ssh.enabled = value
        self.save_config_debounced()
    
    def on_ssh_username_change(self, value: str):
        self.config.ssh.username = value
        self.save_config_debounced()
    
    def on_ssh_password_change(self, value: str):
        self.config.ssh.password = value
        self.save_config_debounced()
    
    def on_ssh_command_change(self, value: str):
        self.config.ssh.command = value
        self.save_config_debounced()
    
    def on_psu_enable_change(self, value: bool):
        self.config.connection.psu_enabled = value
        self.save_config_debounced()
    
    def on_psu_ip_change(self, value: str):
        self.config.connection.psu_address = value
        self.save_config_debounced()
    
    def on_timing_precheck_change(self, value: float):
        self.config.timing.pre_check_delay = value
        self.save_config_debounced()
    
    def on_timing_checkloop_change(self, value: float):
        self.config.timing.loop_check_period = value
        self.save_config_debounced()

    def on_timing_speg_change(self, value: float):
        self.config.timing.poweroff_delay = value
        self.save_config_debounced()
    
    def on_timing_cycle_start_change(self, value: int):
        self.config.timing.cycle_start = value
        self.save_config_debounced()
    
    def on_timing_maxdelay_change(self, value: float):
        self.config.timing.max_startup_delay = value
        self.save_config_debounced()
    
    def on_modbus_enable_change(self, value: bool):
        self.config.modbus.automatic_cycle_count_check_enabled = value
        self.save_config_debounced()
    
    def on_modbus_register_address_change(self, value: int):
        self.config.modbus.register_address = value
        self.save_config_debounced()
    
    def on_modbus_register_value_change(self, value: int):
        self.config.modbus.register_value = value
        self.save_config_debounced()

    def on_modbus_read_press(self):
        ip_list = [ip_from_url(url) for url in self.urls]
        futures_dict = broadcast_modbus_read_register(ip_list, self.config.modbus.register_address, 1)
        for ip,future in futures_dict.items():
                try:
                    regs = future.result()
                    if regs is None or len(regs) == 0:
                        self.log(f"[ERROR] {str(ip)} invalid answer to MODBUS request")
                        continue
                    value = regs[0]
                    self.log(f"[INFO] {str(ip)} address {self.config.modbus.register_address} value {value}")
                    
                except Exception as e:
                    self.log(f"[ERROR] {str(ip)} did not answered to MODBUS request: {e}")

    def on_modbus_write_press(self):
        ip_list = [ip_from_url(url) for url in self.urls]
        futures_dict = broadcast_modbus_write_register(ip_list, self.config.modbus.register_address, self.config.modbus.register_value)
        for ip,future in futures_dict.items():
            try:
                ok = future.result()
                if not ok:
                    self.log(f"[ERROR] {str(ip)} invalid answer to MODBUS request")
                    continue
                
                self.log(f"[INFO] {str(ip)} succesfully answered to MODBUS request")
            except Exception as e:
                self.log(f"[ERROR] {str(ip)} did not answered to MODBUS request: {e}")

    def on_modbus_reset_cycle_count_press(self):
        ip_list = [ip_from_url(url) for url in self.urls]
        futures_dict = broadcast_modbus_write_poweron_counter(ip_list, 0)
        for ip,future in futures_dict.items():
            try:
                ok = future.result()
                if not ok:
                    self.log(f"[ERROR] {str(ip)} invalid answer to MODBUS request")
                    continue
                
                self.log(f"[INFO] {str(ip)} succesfully answered to MODBUS request")
            except Exception as e:
                self.log(f"[ERROR] {str(ip)} did not answered to MODBUS request: {e}")

    def on_modbus_reset_time_count_press(self):
        pass

            
    def on_commands_start_test(self):
        """Avvia il test in un thread separato, reimpostando contatori e flag."""
        if not self.run_test:
            self.run_test = True
            self.is_paused = False
            self.manual_controls_frame.set_pause_status_label("Stato: In esecuzione")
            self.manual_controls_frame.set_pause_button_text("Pausa")
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
    
    def on_commands_stop_test(self):
        """Ferma il test in modo pulito."""
        self.run_test = False
        self.test_stopped_intentionally = True
        self.log("[INFO] Richiesto stop del test.")
    
    def on_commands_toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.manual_controls_frame.set_pause_status_label("Stato: In Pausa")
            self.manual_controls_frame.set_pause_button_text("Riprendi")
            self.log("[INFO] Test in pausa.")
        else:
            self.manual_controls_frame.set_pause_status_label("Stato: In esecuzione")
            self.manual_controls_frame.set_pause_button_text("Pausa")
            self.log("[INFO] Test ripreso.")

    def on_commands_force_power_on(self):
        """Forza manualmente l'accensione dell'alimentatore."""
        try:
            self.log(f"[INFO] Connessione all'alimentatore {self.config.connection.psu_address}...")
            self.psu_connect()
            self.psu_init()
            self.psu_poweron()
            self.log("[INFO] Alimentatore forzato su ON.")
        except Exception as e:
            self.log(f"[ERRORE] Errore durante l'accensione forzata: {str(e)}")

    def on_commands_force_power_off(self):
        """Forza manualmente lo spegnimento dell'alimentatore."""
        try:
            self.log(f"[INFO] Connessione all'alimentatore {self.config.connection.psu_address}...")
            self.psu_connect()
            self.psu_poweroff()
            self.log("[INFO] Alimentatore forzato su OFF.")
        except Exception as e:
            self.log(f"[ERRORE] Errore durante lo spegnimento forzato: {str(e)}")
    
    def on_file_apply_press(self):
        content = self.file_frame.get_text()
        self.urls = url_list_from_csv(content)
        self.refresh_address_table()
        
        url_list_path = os.path.join(os.getcwd(), self.url_list_filename)
        with open(url_list_path, mode="w", encoding="utf-8") as file:
            file.write(content)
        
    def save_config(self):
        config_path = os.path.join(os.getcwd(), self.config_filename)
        data = self.config.as_dict()
        data_json = json.dumps(data)
        with open(config_path, mode="w", encoding="utf-8") as file:
            file.write(data_json)
        print("saved")
    
    def save_config_debounced(self):
        self.save_config_debouncer.call()
    
    def clear_address_table(self):
        self.urls.clear()
        self.refresh_address_table()
    
    def refresh_address_table(self):
        # Pulisce la Treeview
        self.ip_frame.tree_clear()
        
        # Resetta i tempi di rilevamento
        self.detection_times.clear()
        for ip in self.urls:
            self.detection_times[ip] = None
            self.ip_frame.tree_insert(ip, (ip, ""), ('normal',))
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
                self.log_frame.add_log(msg)
                self.log_frame.scroll_down()
        self.after(500, self.process_log_queue)

    def process_gui_queue(self):
        """Gestisce gli aggiornamenti della GUI dalla coda."""
        while True:
            try:
                gui_msg = self.gui_queue.get_nowait()
                if gui_msg[0] == 'update_label':
                    _, label_name, text = gui_msg
                    if label_name == 'anomaly_count_label':
                        self.info_frame.set_anomaly_count_label(text)
                    elif label_name == 'cycle_count_label':
                        self.info_frame.set_cycle_count_label(text)
                elif gui_msg[0] == 'update_tree':
                    ip, detected_time = gui_msg[1], gui_msg[2]
                    self.ip_frame.tree_set(ip, "detected", detected_time)
                elif gui_msg[0] == 'highlight_error':
                    ip = gui_msg[1]
                    self.ip_frame.tree_item(ip, ('error',))
                elif gui_msg[0] == 'remove_tag':
                    ip = gui_msg[1]
                    self.ip_frame.tree_item(ip, ('normal',))
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
    
    def psu_initialized(self):
        self.alimentatore.is_initialized()
    
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
        
        # connect to the PSU only if it's enabled from config
        if self.config.connection.psu_enabled:
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

            self.log(f"[INFO] Ciclo {self.cycle_count}")
            
            # if the remote PSU is enabled and SSH is disabled, switch on the PSU
            # if the remote PSU is enabled and SSH is enabled but it's the first cycle, switch on the PSU
            # otherwise don't switch on the PSU
            if self.config.connection.psu_enabled:
                if not self.config.ssh.enabled or (self.config.ssh.enabled and self.cycle_count == 1):
                    try:
                        self.psu_poweron()
                        self.log(f"[INFO] Alimentatore acceso")                    
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
            
            ip_list = [ip_from_url(url) for url in self.urls]
            
            # check if everyone has the same cycle count reading from registers using MODBUS protocol
            if self.config.modbus.automatic_cycle_count_check_enabled:
                futures_dict = broadcast_modbus_read_poweron_counter(ip_list)
                cycle_count_failure = False
                for ip,future in futures_dict.items():
                    try:
                        regs = future.result()
                        if regs is None:
                            self.log(f"[ERROR] {str(ip)} invalid answer to MODBUS request")
                            continue
                        counter = regs[0]
                        if counter != self.cycle_count:
                            self.log(f"[ERROR] {str(ip)} has a cycle count of {counter} while the current cycle count is {self.cycle_count}")
                            cycle_count_failure = True
                            break

                        self.log(f"[INFO] {str(ip)} cycle count is up-to-date")
                        
                    except Exception as e:
                        self.log(f"[ERROR] {str(ip)} did not answered to MODBUS request: {e}")
                        cycle_count_failure = True
                        break
                
                # if something went wrong during the cycle count check, byee
                if cycle_count_failure:
                    break
                
            
            if self.config.ssh.enabled:
                ssh_failure = False
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
                        ssh_failure = True
                        break
                    except AuthenticationException as e:
                        self.log(f"[ERROR] Authentication exception: {e}")
                        ssh_failure = True
                        break
                    except socket.error as e:
                        self.log(f"[ERROR] socket error: {e}")
                        ssh_failure = True
                        break
                    except SSHException as e:
                        self.log(f"[ERROR] SSH exception: {e}")
                        ssh_failure = True
                        break
                    except Exception as e:
                        self.log(f"[ERROR] Generic error: {e}")
                        ssh_failure = True
                        break
                
                if ssh_failure:
                    break

                if not self.wait_with_stop_check(self.config.timing.poweroff_delay):
                        break
            
            else:
                if self.config.connection.psu_enabled:
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
                        break
                
        if not self.test_stopped_intentionally and self.config.connection.psu_enabled:
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


    def update_elapsed_time(self):
        """Aggiorna il timer dell'interfaccia."""
        if self.run_test and self.test_start_time is not None:
            elapsed = time.time() - self.test_start_time
            hours, remainder = divmod(int(elapsed), 3600)
            minutes, seconds = divmod(remainder, 60)
            elapsed_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
            self.info_frame.set_elapsed_time_label(f"Tempo dall'avvio: {elapsed_str}")
            self.after(1000, self.update_elapsed_time)
    
    def reset_cycle_count(self):
        self.cycle_count = 0
        ip_list = [ip_from_url(url) for url in self.urls]
        futures_dict = broadcast_modbus_write_poweron_counter(ip_list, 0)
        for ip,future in futures_dict.items():
            try:
                ok = future.result()
                if not ok:
                    self.log(f"[ERROR] {str(ip)} invalid answer to MODBUS request")
                    continue
                
                self.log(f"[INFO] {str(ip)} succesfully answered to MODBUS request")
            except Exception as e:
                self.log(f"[ERROR] {str(ip)} did not answered to MODBUS request: {e}")


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
