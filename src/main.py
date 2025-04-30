import tkinter as tk
import threading
import time
import datetime
import queue
import subprocess
from urllib3.exceptions import InsecureRequestWarning
import requests
import os
import json
from ordered_set import OrderedSet
from config import TestBenchConfig
from gui import FileFrame, InfoFrame, IpTableFrame, LogFrame, ManualControlsFrame, ModbusFrame, PsuFrame, SSHFrame, TimingFrame
from enum import Enum
from dp832 import dp832
from utils import broadcast_modbus_read_poweron_counter, broadcast_modbus_read_register, broadcast_modbus_write_poweron_counter, broadcast_modbus_write_register, broadcast_ping, broadcast_ssh_command, get_current_git_commit_hash, ip_from_url, url_list_from_csv

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class ProcessingState(Enum):
    Init = 1
    PsuInit = 2
    Setup = 3
    PsuPowerOn = 4
    PingDelay = 5
    Ping = 6
    ModbusDelay = 7
    Modbus = 8
    SshDelay = 9
    Ssh = 10
    ReverseModbusDelay = 11
    ReverseModbus = 12
    ReversePingDelay = 13
    ReversePing = 14
    PsuPowerOffDelay = 15
    PsuPowerOff = 16
    Failure = 17
    SetupDelay = 18

class ProcessingStatus:
    state: ProcessingState
    waiting_steps: int
    total_waiting_steps: int
    
    def __init__(self):
        self.state = ProcessingState.Init
        self.waiting_steps = 0
        self.total_waiting_steps = 0

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


class TestbenchFrames:
    psu_frame: PsuFrame
    timing_frame: TimingFrame
    ssh_frame: SSHFrame
    modbus_frame: ModbusFrame
    file_frame: FileFrame
    manual_controls_frame: ManualControlsFrame
    info_frame: InfoFrame
    ip_frame: IpTableFrame
    log_frame: LogFrame
    
    def __init__(
        self,
        psu_frame: PsuFrame,
        timing_frame: TimingFrame,
        ssh_frame: SSHFrame,
        modbus_frame: ModbusFrame,
        file_frame: FileFrame,
        manual_controls_frame: ManualControlsFrame,
        info_frame: InfoFrame,
        ip_frame: IpTableFrame,
        log_frame: LogFrame
    ):    
        self.psu_frame = psu_frame
        self.timing_frame = timing_frame
        self.ssh_frame = ssh_frame
        self.modbus_frame = modbus_frame
        self.file_frame = file_frame
        self.manual_controls_frame = manual_controls_frame
        self.info_frame = info_frame
        self.ip_frame = ip_frame
        self.log_frame = log_frame

class TestbenchApp(tk.Tk):
    url_list_filename = 'urls.csv'
    config_filename = 'config.json'
    window_title = "Rigol Test GUI"
    window_w = 1280
    window_h = 800
    save_config_debouncer: Debouncer
    status: ProcessingStatus
    modbus_timeout: float = 5
    ping_timeout: float = 3
    frames: TestbenchFrames

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
        
        self.status = ProcessingStatus()

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

        # TOP RIGHT FRAME
        top_right_frame = tk.Frame(top_frame)
        top_right_frame.grid(row=0, column=1, sticky="nsew")
        
        # BOTTOM FRAME
        bottom_frame = tk.Frame(self)
        bottom_frame.grid(row=1, column=0, sticky="nsew")
        
        # BOTTOM LEFT FRAME
        bottom_left_frame = tk.Frame(bottom_frame)
        bottom_left_frame.grid(row=0, column=0, sticky="nsew")
        
        # BOTTOM RIGHT FRAME
        bottom_right_frame = tk.Frame(bottom_frame)
        bottom_right_frame.grid(row=0, column=1, sticky="nsew")
        
        psu_frame = PsuFrame(top_left_frame, 0, 0, 5, 5, "nsew")
        timing_frame = TimingFrame(top_left_frame, 1, 0, 5, 5, "nsew")
        ssh_frame = SSHFrame(top_left_frame, 2, 0, 5, 5, "nsew")
        modbus_frame = ModbusFrame(top_left_frame, 3, 0, 5, 5, "nsew")
        manual_controls_frame = ManualControlsFrame(bottom_left_frame, 0, 0, 5, 5, "nsew")
        info_frame = InfoFrame(bottom_left_frame, 1, 0, 5, 5, "nsew")
        ip_frame = IpTableFrame(bottom_left_frame, 2, 0, 5, 5, "nsew")
        file_frame = FileFrame(bottom_right_frame, 0, 0, 5, 5, "nsew")
        log_frame = LogFrame(top_right_frame, 0, 0, 5, 5, "nsew")
        
        self.frames = TestbenchFrames(psu_frame, timing_frame, ssh_frame, modbus_frame, file_frame, manual_controls_frame, info_frame, ip_frame, log_frame)
        
        self.frames.psu_frame.set_psu_enabled(self.config.connection.psu_enabled)
        self.frames.psu_frame.set_psu_ip(self.config.connection.psu_address)
        self.frames.psu_frame.set_psu_enabled_change_cb(self.on_psu_enable_change)
        self.frames.psu_frame.set_psu_ip_change_cb(self.on_psu_ip_change)
        
        self.frames.timing_frame.set_precheck(self.config.timing.pre_check_delay)
        self.frames.timing_frame.set_checkloop(self.config.timing.loop_check_period)
        self.frames.timing_frame.set_maxdelay(self.config.timing.max_startup_delay)
        self.frames.timing_frame.set_speg(self.config.timing.poweroff_delay)
        self.frames.timing_frame.set_cycle_start(self.config.timing.cycle_start)
        
        self.frames.timing_frame.set_precheck_cb(self.on_timing_precheck_change)
        self.frames.timing_frame.set_maxdelay_cb(self.on_timing_maxdelay_change)
        self.frames.timing_frame.set_speg_cb(self.on_timing_speg_change)
        self.frames.timing_frame.set_checkloop_cb(self.on_timing_checkloop_change)
        self.frames.timing_frame.set_cycle_start_cb(self.on_timing_cycle_start_change)
        
        self.frames.ssh_frame.set_ssh_enabled(self.config.ssh.enabled)
        self.frames.ssh_frame.set_username(self.config.ssh.username)
        self.frames.ssh_frame.set_password(self.config.ssh.password)
        self.frames.ssh_frame.set_command(self.config.ssh.command)
        
        self.frames.ssh_frame.set_ssh_enabled_change_cb(self.on_ssh_enabled_change)
        self.frames.ssh_frame.set_username_change_cb(self.on_ssh_username_change)
        self.frames.ssh_frame.set_password_change_cb(self.on_ssh_password_change)
        self.frames.ssh_frame.set_command_change_cb(self.on_ssh_command_change)
        
        self.frames.modbus_frame.set_modbus_enable(self.config.modbus.automatic_cycle_count_check_enabled)
        self.frames.modbus_frame.set_register_address(self.config.modbus.register_address)
        self.frames.modbus_frame.set_register_value(self.config.modbus.register_value)
        
        self.frames.modbus_frame.set_modbus_enable_change_cb(self.on_modbus_enable_change)
        self.frames.modbus_frame.set_register_address_change_cb(self.on_modbus_register_address_change)
        self.frames.modbus_frame.set_register_value_change_cb(self.on_modbus_register_value_change)
        self.frames.modbus_frame.set_read_register_press_cb(self.on_modbus_read_press)
        self.frames.modbus_frame.set_write_register_press_cb(self.on_modbus_write_press)
        self.frames.modbus_frame.set_reset_cycle_count_press_cb(self.on_modbus_reset_cycle_count_press)
        self.frames.modbus_frame.set_reset_time_count_press_cb(self.on_modbus_reset_time_count_press)
        
        self.frames.manual_controls_frame.set_start_button_press_cb(self.on_commands_start_test)
        self.frames.manual_controls_frame.set_stop_button_press_cb(self.on_commands_stop_test)
        self.frames.manual_controls_frame.set_pause_button_press_cb(self.on_commands_toggle_pause)
        self.frames.manual_controls_frame.set_force_on_button_press_cb(self.on_commands_force_power_on)
        self.frames.manual_controls_frame.set_force_off_button_press_cb(self.on_commands_force_power_off)
        
        url_list_path = os.path.join(os.getcwd(), self.url_list_filename)
        with open(url_list_path) as f: content = f.read()
        
        self.frames.file_frame.load_text(content)
        self.frames.file_frame.set_apply_button_press_cb(self.on_file_apply_press)
        
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
        ip_list = [ip for ip in ip_list if ip is not None]
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
        ip_list = [ip for ip in ip_list if ip is not None]
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
        ip_list = [ip for ip in ip_list if ip is not None]
        futures_dict = broadcast_modbus_write_poweron_counter(ip_list, 0, self.modbus_timeout)
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
            self.frames.manual_controls_frame.set_pause_status_label("Stato: In esecuzione")
            self.frames.manual_controls_frame.set_pause_button_text("Pausa")
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
            test_thread = threading.Thread(target=self.test_loop, daemon=True)
            test_thread.start()
    
    def on_commands_stop_test(self):
        """Ferma il test in modo pulito."""
        self.run_test = False
        self.test_stopped_intentionally = True
        self.log("[INFO] Richiesto stop del test.")
    
    def on_commands_toggle_pause(self):
        self.is_paused = not self.is_paused
        if self.is_paused:
            self.frames.manual_controls_frame.set_pause_status_label("Stato: In Pausa")
            self.frames.manual_controls_frame.set_pause_button_text("Riprendi")
            self.log("[INFO] Test in pausa.")
        else:
            self.frames.manual_controls_frame.set_pause_status_label("Stato: In esecuzione")
            self.frames.manual_controls_frame.set_pause_button_text("Pausa")
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
        content = self.frames.file_frame.get_text()
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
        self.frames.ip_frame.tree_clear()
        
        # Resetta i tempi di rilevamento
        self.detection_times.clear()
        for ip in self.urls:
            self.detection_times[ip] = None
            self.frames.ip_frame.tree_insert(ip, (ip, ""), ('normal',))
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
                self.frames.log_frame.add_log(msg)
                self.frames.log_frame.scroll_down()
        self.after(500, self.process_log_queue)

    def process_gui_queue(self):
        """Gestisce gli aggiornamenti della GUI dalla coda."""
        while True:
            try:
                gui_msg = self.gui_queue.get_nowait()
                if gui_msg[0] == 'update_label':
                    _, label_name, text = gui_msg
                    if label_name == 'anomaly_count_label':
                        self.frames.info_frame.set_anomaly_count_label(text)
                    elif label_name == 'cycle_count_label':
                        self.frames.info_frame.set_cycle_count_label(text)
                elif gui_msg[0] == 'update_tree':
                    ip, detected_time = gui_msg[1], gui_msg[2]
                    self.frames.ip_frame.tree_set(ip, "detected", detected_time)
                elif gui_msg[0] == 'highlight_error':
                    ip = gui_msg[1]
                    self.frames.ip_frame.tree_item(ip, ('error',))
                elif gui_msg[0] == 'remove_tag':
                    ip = gui_msg[1]
                    self.frames.ip_frame.tree_item(ip, ('normal',))
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
        url_futures = broadcast_ping(url_list, self.ping_timeout)
        
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
    def ping_procedure(self) -> bool:
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
    
    # returns True every url has not responded to the ping, otherwise False
    def reverse_ping_procedure(self) -> bool:
        # ping only the URLs that have answered
        url_list_to_ping = set([url for url in self.urls if self.detection_times[url] is not None])
        detection_times = self.ping_with_detection_time(url_list_to_ping)
        # remove the valid responses
        detection_times_valid = {k: v for k,v in detection_times.items() if v is None}
        
        for url,detection_time in detection_times_valid.items():
            self.detection_times[url] = detection_time
            self.gui_queue.put(('update_tree', url, ""))
            self.log(f"[INFO] URL {url} stopped answering")
        
        if all(self.detection_times[ip] is None for ip in self.urls):
            return True

        return False
    
    # returns True if the modbus procedure has succesfully finished, otherwise False
    def modbus_check_procedure(self) -> bool:
        self.log(f"[INFO] MODBUS procedure started")
        ip_list = [ip_from_url(url) for url in self.urls]
        ip_list = [ip for ip in ip_list if ip is not None]
        futures_dict = broadcast_modbus_read_poweron_counter(ip_list, self.modbus_timeout)
        cycle_count_failure = False
        for ip,future in futures_dict.items():
            try:
                regs = future.result()
                if regs is None:
                    self.log(f"[ERROR] {str(ip)} invalid answer to MODBUS request")
                    cycle_count_failure = True
                    break
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
            self.log("[INFO] MODBUS procedure failed")
        else:
            self.log("[INFO] MODBUS procedure succesfully finished")

        return not cycle_count_failure

    def reverse_modbus_check_procedure(self) -> bool:
        ip_list = [ip_from_url(url) for url in self.urls]
        ip_list = [ip for ip in ip_list if ip is not None]
        futures_dict = broadcast_modbus_read_poweron_counter(ip_list, self.modbus_timeout)
        cycle_count_success = True
        for ip,future in futures_dict.items():
            try:
                _ = future.result()
                cycle_count_success = False
                break     
            except Exception as e:
                pass
        
        return cycle_count_success
    
    def ssh_procedure(self) -> bool:
        self.log("[INFO] SSH procedure started")
        ssh_failure = False
        ip_list = [ip_from_url(url) for url in self.urls]
        ip_list = [ip for ip in ip_list if ip is not None]
        futures_dict = broadcast_ssh_command(ip_list, self.config.ssh.username, self.config.ssh.password, self.config.ssh.command)
        for ip,future in futures_dict.items():
            try:
                future.result()
                self.log(f"[INFO] SSH command succesfully sent to {str(ip)}")
            except Exception as e:
                self.log(f"[ERROR] {e}")
                ssh_failure = True
                break
        
        if ssh_failure:
            self.log("[INFO] SSH procedure failed")
        else:        
            self.log("[INFO] SSH procedure succesfully finished")

        return not ssh_failure
    
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
    
    def test_step(self, dt: float):
        match self.status.state:
            
            case ProcessingState.Init:
                if self.config.connection.psu_enabled:
                    self.status.state = ProcessingState.PsuInit
                else:
                    self.status.state = ProcessingState.Setup
            
            case ProcessingState.PsuInit:
                try:
                    self.psu_connect()
                    self.psu_init()
                except Exception as e:
                    self.log(f"[ERRORE] Impossibile connettersi all'alimentatore: {str(e)}")
                    self.status.state = ProcessingState.Failure
                else:
                    if not self.config.ssh.enabled or \
                        (self.config.ssh.enabled and (self.cycle_count - 1) == self.config.timing.cycle_start):
                        self.status.state = ProcessingState.PsuPowerOn
            
            case ProcessingState.PsuPowerOn:
                try:
                    self.psu_poweron()
                except Exception as e:
                    self.log(f"[ERRORE] Error while trying to switch on the PSU: {str(e)}")
                    self.status.state = ProcessingState.Failure
                else:
                    self.log(f"[INFO] PSU is ON")
                    self.status.state = ProcessingState.PingDelay
                    self.status.total_waiting_steps = int(self.config.timing.pre_check_delay / dt)
            
            case ProcessingState.SetupDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.Setup
                    self.status.waiting_steps = 0
            
            case ProcessingState.Setup:
                self.cycle_defectives.clear()
                # TODO try to make t0 local
                self.t0 = None
                self.cycle_count += 1
                self.gui_queue.put(('update_label', 'cycle_count_label', f"Accensioni eseguite: {self.cycle_count}"))
                
                # clear detection times and GUI
                for ip in self.urls:
                    self.detection_times[ip] = None
                    self.gui_queue.put(('update_tree', ip, ""))
                    self.gui_queue.put(('remove_tag', ip))
                
                self.log(f"[INFO] Cycle {self.cycle_count}")
                if self.config.connection.psu_enabled:
                    self.status.state = ProcessingState.PsuPowerOn
                else:
                    self.status.state = ProcessingState.PingDelay
            
            case ProcessingState.PingDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.Ping
                    self.status.waiting_steps = 0

            case ProcessingState.Ping:
                if not self.ping_procedure():
                    return
                if self.config.modbus.automatic_cycle_count_check_enabled:
                    self.status.state = ProcessingState.ModbusDelay
                elif self.config.ssh.enabled:
                    self.status.state = ProcessingState.SshDelay
                elif self.config.connection.psu_enabled:
                    self.status.state = ProcessingState.PsuPowerOffDelay
                else:
                    self.status.state = ProcessingState.Setup
            
            case ProcessingState.ModbusDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.Modbus
                    self.status.waiting_steps = 0
            
            case ProcessingState.Modbus:
                if not self.modbus_check_procedure():
                    self.status.state = ProcessingState.Failure
                    return
                if self.config.ssh.enabled:
                    self.status.state = ProcessingState.SshDelay
                elif self.config.connection.psu_enabled:
                    self.status.state = ProcessingState.PsuPowerOffDelay
                else:
                    self.status.state = ProcessingState.Setup
            
            case ProcessingState.SshDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.Ssh
                    self.status.waiting_steps = 0
            
            case ProcessingState.Ssh:
                if not self.ssh_procedure():
                    self.status.state = ProcessingState.Failure
                    return
                if self.config.modbus.automatic_cycle_count_check_enabled:
                    self.status.state = ProcessingState.ReverseModbusDelay
                else:
                    self.status.state = ProcessingState.ReversePingDelay
            
            case ProcessingState.ReversePingDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.ReversePing
                    self.status.waiting_steps = 0
            
            case ProcessingState.ReversePing:
                if not self.reverse_ping_procedure():
                    return
                self.status.state = ProcessingState.Setup
            
            case ProcessingState.ReverseModbusDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.ReverseModbus
                    self.status.waiting_steps = 0
            
            case ProcessingState.ReverseModbus:
                if not self.reverse_modbus_check_procedure():
                    return
                self.status.state = ProcessingState.ReversePingDelay
            
            case ProcessingState.PsuPowerOffDelay:
                self.status.waiting_steps += 1
                if self.status.waiting_steps == self.status.total_waiting_steps:
                    self.status.state = ProcessingState.PsuPowerOff
                    self.status.waiting_steps = 0

            case ProcessingState.PsuPowerOff:
                try:
                    self.psu_poweroff()
                except Exception as e:
                    self.log(f"[ERRORE] Error while trying to switch off the PSU: {str(e)}")
                    self.status.state = ProcessingState.Failure
                else:
                    self.log(f"[INFO] PSU is OFF")
                    self.status.state = ProcessingState.SetupDelay
            
            case ProcessingState.Failure:
                pass
    
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
        
        if not self.run_test:
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
            
            # clear detection times and GUI
            for ip in self.urls:
                self.detection_times[ip] = None
                self.gui_queue.put(('update_tree', ip, ""))
                self.gui_queue.put(('remove_tag', ip))
            
            self.log(f"[INFO] Cycle {self.cycle_count}")
            
            # if the remote PSU is enabled and SSH is disabled, switch on the PSU
            # if the remote PSU is enabled and SSH is enabled but it's the first cycle, switch on the PSU
            # otherwise don't switch on the PSU
            if self.config.connection.psu_enabled:
                if not self.config.ssh.enabled or (self.config.ssh.enabled and (self.cycle_count - 1) == self.config.timing.cycle_start):
                    try:
                        self.psu_poweron()
                        self.log(f"[INFO] PSU is ON")                    
                    except Exception as e:
                        self.log(f"[ERRORE] Error while trying to switch on the PSU: {str(e)}")
                        continue
            
            # wait for precheck delay
            self.log(f"[INFO] Waiting {self.config.timing.pre_check_delay}s before starting the ping procedure")
            if not self.wait_with_stop_check(self.config.timing.pre_check_delay):
                self.log("[INFO] Test stopped, exiting test loop")
                break
            
            # start the pinging loop
            # it exits if the ping is successfull (every URL has answered)
            self.log(f"[INFO] Ping procedure started")
            while self.wait_with_stop_check(self.config.timing.loop_check_period):
                if self.is_paused:
                    self.log("[INFO] Ping procedure paused")
                    continue
                if self.ping_procedure():
                    break
            
            if not self.run_test:
                self.log("[INFO] Ping procedure stopped, exiting test loop")
                break
            
            self.log("[INFO] Ping procedure succesfully finished")
            
            # update the anomaly count using the size of the cycle_defectives set
            self.anomaly_count = self.anomaly_count + len(self.cycle_defectives)
            self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
            
            # check if everyone has the same cycle count reading from registers using MODBUS protocol
            if self.config.modbus.automatic_cycle_count_check_enabled:
                modbus_procedure_success = self.modbus_check_procedure()
                if not modbus_procedure_success:
                    break
            
            if self.config.ssh.enabled:
                self.log("[INFO] Waiting 5 seconds before starting SSH procedure")
                if not self.wait_with_stop_check(5):
                    self.log("[INFO] SSH procedure stopped, exiting test loop")
                    break
                
                ssh_procedure_success = self.ssh_procedure()
                if not ssh_procedure_success:
                    break
                
                if not self.wait_with_stop_check(self.config.timing.poweroff_delay):
                    self.log(f"[INFO] Test stopped, exiting test loop")
                    break
            
            elif self.config.connection.psu_enabled:
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
            
            if self.config.modbus.automatic_cycle_count_check_enabled:
                self.log(f"[INFO] Reverse MODBUS procedure started")            
                while self.wait_with_stop_check(self.config.timing.loop_check_period):
                    if self.is_paused:
                        self.log("[INFO] Reverse MODBUS procedure paused")
                        continue
                    if self.reverse_modbus_check_procedure():
                        break
                
                if not self.run_test:
                    self.log("[INFO] Reverse MODBUS procedure stopped, exiting test loop")
                    break
            
                self.log("[INFO] Reverse MODBUS procedure succesfully finished")
            
            # start the reverse pinging loop
            # it exits if the ping is failed (no URL has answered)
            self.log(f"[INFO] Reverse ping procedure started")
            while self.wait_with_stop_check(self.config.timing.loop_check_period):
                if self.is_paused:
                    self.log("[INFO] Reverse ping procedure paused")
                    continue
                if self.reverse_ping_procedure():
                    break
            
            if not self.run_test:
                self.log("[INFO] Ping procedure stopped, exiting test loop")
                break
            
            self.log("[INFO] Reverse ping procedure succesfully finished")
            
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
            self.frames.info_frame.set_elapsed_time_label(f"Tempo dall'avvio: {elapsed_str}")
            self.after(1000, self.update_elapsed_time)
    
    def reset_cycle_count(self):
        self.cycle_count = 0
        self.gui_queue.put(('update_label', 'cycle_count_label', f"Accensioni eseguite: {self.cycle_count}"))
        ip_list = [ip_from_url(url) for url in self.urls]
        ip_list = [ip for ip in ip_list if ip is not None]
        futures_dict = broadcast_modbus_write_poweron_counter(ip_list, 0, self.modbus_timeout)
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
    app = TestbenchApp(version)
    app.mainloop()
