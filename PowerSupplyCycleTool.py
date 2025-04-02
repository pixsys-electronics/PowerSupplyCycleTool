import tkinter as tk
from tkinter import ttk, scrolledtext
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

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

class TestBenchConnectionConfig:
    psu_address: IPv4Address
    start_address: IPv4Address
    end_address: IPv4Address
    url: str

    def __init__(self, psu_address: IPv4Address, start_address: IPv4Address, end_address: IPv4Address, url: str):
        self.psu_address = psu_address
        self.start_address = start_address
        self.end_address = end_address
        self.url = url

class TestBenchTimingConfig:
    pre_check_delay: float
    loop_check_period: float
    poweroff_delay: float
    max_startup_delay: float

    def __init__(self, pre_check_delay: float, loop_check_period: float, poweroff_delay: float, max_startup_delay: float):
        self.pre_check_delay = pre_check_delay
        self.loop_check_period = loop_check_period
        self.poweroff_delay = poweroff_delay
        self.max_startup_delay = max_startup_delay
        

class TestBenchConfig:
    connection: TestBenchConnectionConfig
    timing: TestBenchTimingConfig

    def __init__(self, connection: TestBenchConnectionConfig, timing: TestBenchTimingConfig):
        self.connection = connection
        self.timing = timing
    
    @staticmethod
    def from_json(file_path: str):
        data = config_from_json(file_path)
        
        connection = data["connection"]
        psu_address = ip_address(connection["psu_address"])
        start_address = ip_address(connection["start_address"])
        end_address = ip_address(connection["end_address"])
        url = connection["url"]
        connection = TestBenchConnectionConfig(psu_address, start_address, end_address, url)

        timing = data["timing"]
        pre_check_delay = float(timing["pre_check_delay"])
        loop_check_period = float(timing["loop_check_period"])
        poweroff_delay = float(timing["poweroff_delay"])
        max_startup_delay = float(timing["max_startup_delay"])
    
        timing = TestBenchTimingConfig(pre_check_delay, loop_check_period, poweroff_delay, max_startup_delay)

        return TestBenchConfig(connection, timing)


# Sostituisci con la tua implementazione o libreria effettiva per l'alimentatore Rigol.
from dp832 import dp832

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

class RigolTestApp(tk.Tk):
    ip_addresses_config_path = 'config.csv'

    def __init__(self, config: TestBenchConfig):
        super().__init__()
        self.geometry("1280x800")
        self.title("Rigol Test GUI")
        self.config: TestBenchConfig = config
        
        # Stringa di verifica configurabile (viene impostata tramite GUI)
        self.verification_suffix = self.config.connection.url
        
        # Lista IP e tempi di rilevamento
        self.urls: OrderedSet[str] = OrderedSet()
        self.detection_times = {}
        
        # Code per log e comunicazioni verso la GUI
        self.log_queue = queue.Queue()
        self.gui_queue = queue.Queue()
        
        # Controllo del loop di test
        self.run_test = False
        self.test_thread = None
        self.test_start_time = None
        
        # Contatori
        self.cycle_count = 0
        self.cycle_start_count = 0
        self.anomaly_count = 0
        
        # IP dell'alimentatore
        self.dp832_host = None
        
        # File di report
        self.report_file = None
        
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
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)  # l'area log

        # TOP FRAME
        top_frame = tk.Frame(self)
        top_frame.grid(row=0, column=0, sticky="new")

        # TOP LEFT FRAME
        top_left_frame = tk.Frame(top_frame)
        top_left_frame.grid(row=0, column=0, sticky="nw")

        self.init_psu_frame(top_left_frame, 0, 0)
        self.init_params_frame(top_left_frame, 1, 0)
        
        # TOP RIGHT FRAME
        top_right_frame = tk.Frame(top_frame)
        top_right_frame.grid(row=0, column=1, sticky="ne")

        self.init_url_file_frame(top_right_frame, 0, 0)
        
        # BOTTOM FRAME
        bottom_frame = tk.Frame(self)
        bottom_frame.grid(row=1, column=0, sticky="sew")

        # BOTTOM LEFT FRAME
        bottom_left_frame = tk.Frame(bottom_frame)
        bottom_left_frame.grid(row=0, column=0, sticky="new")

        self.init_info_frame(bottom_left_frame, 0, 0)
        self.init_command_frame(bottom_frame, 1, 0)
        self.init_ip_table(bottom_frame, 2, 0)
        
        # BOTTOM RIGHT FRAME
        bottom_right_frame = tk.Frame(bottom_frame)
        bottom_right_frame.grid(row=0, column=1)

        self.init_log_frame(bottom_right_frame, 0, 0)
        
    
    def init_url_file_frame(self, parent, row, col):
        self.url_file_frame = ttk.Frame(parent)
        self.url_file_frame.grid(row=row, column=col, padx=5, pady=5)

        self.url_file = scrolledtext.ScrolledText(self.url_file_frame)
        self.url_file.grid(row=0, column=0)
        self.url_file.config(height=20)

        url_list_path = os.path.join(os.getcwd(), self.ip_addresses_config_path)
        with open(url_list_path) as f: content = f.read()
        self.url_file.insert('1.0', content)

        self.apply_button = ttk.Button(self.url_file_frame, text="Apply", command=self.apply_url_file)
        self.apply_button.grid(row=1, column=0, padx=5, pady=5)
    
    def init_info_frame(self, parent, row, col):
        # Frame 3: Info frame (timer, contatori)
        info_frame = ttk.Frame(parent)
        info_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")

        self.elapsed_time_label = ttk.Label(info_frame, text="Test non ancora partito.")
        self.elapsed_time_label.pack(side="left", padx=5)

        self.cycle_count_label = ttk.Label(info_frame, text="Accensioni eseguite: 0")
        self.cycle_count_label.pack(side="left", padx=20)

        self.anomaly_count_label = ttk.Label(info_frame, text="Accensioni con anomalia: 0")
        self.anomaly_count_label.pack(side="left", padx=20)
    
    def init_command_frame(self, parent, row, col):
        # Frame 4: Controlli manuali
        self.manual_frame = ttk.LabelFrame(parent, text="Controlli Manuali")
        self.manual_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")

        self.manual_frame.grid_columnconfigure(3, weight=1)

        self.pause_button = ttk.Button(self.manual_frame, text="Pausa", command=self.toggle_pause)
        self.pause_button.grid(row=0, column=0, padx=5, pady=5)

        self.force_on_button = ttk.Button(self.manual_frame, text="Forza ON", command=self.force_power_on)
        self.force_on_button.grid(row=0, column=1, padx=5, pady=5)

        self.force_off_button = ttk.Button(self.manual_frame, text="Forza OFF", command=self.force_power_off)
        self.force_off_button.grid(row=0, column=2, padx=5, pady=5)

        self.pause_status_label = ttk.Label(self.manual_frame, text="Stato: In esecuzione")
        self.pause_status_label.grid(row=0, column=3, padx=5, pady=5, sticky="w")
    
    def init_params_frame(self, parent, row, col):
        # Frame 2: Configurazione Tempi
        self.times_frame = ttk.LabelFrame(parent, text="Configurazione Tempi (in secondi)")
        self.times_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")

        self.times_frame.grid_columnconfigure(1, weight=1)

        labels_entries = [
            ("Attesa prima di controllare IP (Pre-check):", "entry_precheck", self.config.timing.pre_check_delay),
            ("Intervallo tra controlli IP:", "entry_checkloop", self.config.timing.loop_check_period),
            ("Durata spegnimento:", "entry_speg", self.config.timing.poweroff_delay),
            ("Massimo ritardo avvio dispositivi:", "entry_maxdelay", self.config.timing.max_startup_delay),
            ("Conteggio di partenza:", "entry_cycle_start", 0)
        ]

        for idx, (label_text, entry_name, default_value) in enumerate(labels_entries):
            ttk.Label(self.times_frame, text=label_text).grid(row=idx, column=0, sticky="w", padx=5, pady=2)
            entry = ttk.Entry(self.times_frame, width=6)
            entry.insert(0, str(default_value))
            entry.grid(row=idx, column=1, sticky="w", padx=5, pady=2)
            setattr(self, entry_name, entry)

        self.btn_applica_tempi = ttk.Button(self.times_frame, text="Applica Impostazioni", 
                                            command=self.apply_time_settings)
        self.btn_applica_tempi.grid(row=len(labels_entries), column=0, columnspan=2, pady=5)
    
    def init_psu_frame(self, parent, row, col):
        # Frame 1: IP Alimentatore, Range IP e URL di verifica
        self.range_frame = ttk.LabelFrame(parent, text="Alimentatore")
        self.range_frame.grid(row=row, column=col, padx=10, pady=5, sticky="ew")

        self.range_frame.grid_columnconfigure(6, weight=1)

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
        self.controls_frame = ttk.Frame(parent)
        self.controls_frame.grid(row=row, column=col, padx=10, pady=5, sticky="nsew")

        self.controls_frame.grid_columnconfigure(0, weight=1)
        self.controls_frame.grid_rowconfigure(1, weight=1)

        # Pulsanti Start/Stop
        button_frame = ttk.Frame(self.controls_frame)
        button_frame.grid(row=0, column=0, sticky="ew")

        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_test)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_test)
        self.stop_button.pack(side="left", padx=5)

        # Area Log
        ttk.Label(self.controls_frame, text="Log:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(self.controls_frame, wrap=tk.WORD)
        self.log_text.grid(row=2, column=0, sticky="nsew")
        self.log_text.config(height=10)

    
    def apply_url_file(self):
        content = self.url_file.get("1.0", "end-1c")
        self.urls = url_list_from_csv(content)
        self.refresh_address_table()
        
        url_list_path = os.path.join(os.getcwd(), self.ip_addresses_config_path)
        with open(url_list_path, mode="w", encoding="utf-8") as file:
            file.write(content)

    def ip_responds(self, ip):
        """Verifica se l'IP risponde utilizzando requests, usando la configurazione dell'URL."""
        protocol = "http" if self.verification_suffix.startswith(":80") else "https"
        url = f"{protocol}://{ip}{self.verification_suffix}"
        try:
            response = requests.get(url, verify=False, timeout=3)
            return response.status_code == 200
        except requests.RequestException as e:
            self.log(f"[DEBUG] IP {ip} non risponde: {e}")
            return False

    def ip_responds_curl(self, url: str):
        try:
            result = subprocess.run(
                ['curl', '-k', '-s', '-o', '/dev/null', '-w', '%{http_code}', url],
                timeout=3,
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == '200'
        except subprocess.TimeoutExpired:
            self.log(f"[DEBUG] IP {url} non risponde: Timeout")
            return False
        except Exception as e:
            self.log(f"[DEBUG] IP {url} verifica fallita: {e}")
            return False
    
    def clear_address_table(self):
        self.urls.clear()
        self.refresh_address_table()
    
    def retrieve_ip_list_from_config(self):
        filepath = self.ip_addresses_config_path
        filepath = os.path.join(os.getcwd(), filepath)
        with open(filepath, mode="r", encoding="utf-8") as file:
            csv_content = file.read()
            data = url_list_from_csv(csv_content)
            self.urls.update(data)
            for entry in data:
                self.log(f"[INFO] IP found: {entry}")
            
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
        
    def apply_time_settings(self):
        """
        Applica i tempi configurati dall'utente.
        """
        try:
            self.config.timing.pre_check_delay   = float(self.entry_precheck.get())
            self.config.timing.loop_check_period  = float(self.entry_checkloop.get())
            self.config.timing.poweroff_delay = float(self.entry_speg.get())
            self.config.timing.max_startup_delay = float(self.entry_maxdelay.get())
            self.cycle_start_count = float(self.entry_cycle_start.get())
            self.log("[INFO] Impostazioni aggiornate (tempi, max delay, conteggio).")
        except ValueError:
            self.log("[ERRORE] Inserire valori numerici nei campi configurazione.")

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
        try:
            now_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{now_str}.csv"
            return filename
        except Exception as e:
            self.log(f"[ERRORE] Errore nella creazione del nome del report: {str(e)}")
            return None

    def write_test_start_line(self):
        """Scrive una riga di intestazione nel file di report per l'inizio del test."""
        if not self.report_file:
            self.log("[ERRORE] Nome del file di report non definito.")
            return
        start_time_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"### Test started at {start_time_str}\n"
        try:
            with open(self.report_file, "a", encoding="utf-8") as f:
                f.write(line)
        except Exception as e:
            self.log(f"[ERRORE] Errore durante la scrittura del file di report: {str(e)}")

    def test_loop(self):
        """
        Loop principale di test:
        - Accende l'alimentatore.
        - Verifica in parallelo la risposta degli IP tramite ip_responds_curl.
        - Utilizza la stringa configurabile per costruire l'URL di verifica.
        """
        alimentatore = dp832()
        
        if not self.dp832_host:
            self.log("[ERRORE] IP alimentatore non configurato! Interrompo.")
            self.run_test = False
            return
        
        self.log(f"[INFO] Connessione all'alimentatore {self.dp832_host}...")
        try:
            alimentatore.connect(self.dp832_host)
            alimentatore.set_voltage(1, 26.000)
            alimentatore.set_voltage(2, 26.000)
        except Exception as e:
            self.log(f"[ERRORE] Impossibile connettersi all'alimentatore: {str(e)}")
            self.run_test = False
            return
        
        while self.run_test:
            # Gestione pausa
            while hasattr(self, 'is_paused') and self.is_paused and self.run_test:
                time.sleep(0.5)
                continue

            if not self.run_test:
                break

            self.cycle_count += 1
            self.gui_queue.put(('update_label', 'cycle_count_label', f"Accensioni eseguite: {self.cycle_count}"))
            
            current_cycle_defectives = set()
            
            self.log(f"[INFO] (Ciclo {self.cycle_count}) Accendo alimentatore (canali 1 e 2)...")
            try:
                for channel in (1, 2):
                    alimentatore.select_output(channel)
                    alimentatore.toggle_output(channel, 'ON')
            except Exception as e:
                self.log(f"[ERRORE] Errore durante l'accensione: {str(e)}")
                continue
            
            for ip in self.urls:
                self.detection_times[ip] = None
                self.gui_queue.put(('update_tree', ip, ""))
                self.gui_queue.put(('remove_tag', ip))
            
            self.log(f"[INFO] Attendo {self.config.timing.pre_check_delay} secondi prima del controllo degli IP.")
            if not self.wait_with_stop_check(self.config.timing.pre_check_delay):
                break

            t0 = None
            self.log("[INFO] Inizio controllo rapido degli IP ogni 100ms.")
            while self.run_test:
                # Gestione pausa
                while hasattr(self, 'is_paused') and self.is_paused and self.run_test:
                    time.sleep(0.5)
                    continue
                
                if not self.run_test:
                    break

                with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
                    future_to_ip = {executor.submit(self.ip_responds_curl, ip): ip for ip in self.urls if self.detection_times[ip] is None}
                    
                    for future in concurrent.futures.as_completed(future_to_ip):
                        ip = future_to_ip[future]
                        try:
                            response = future.result()
                        except Exception as exc:
                            self.log(f"[ERRORE] Verifica IP {ip} ha generato un'eccezione: {exc}")
                            continue
                        else:
                            if response:
                                detection_time = datetime.datetime.now()
                                self.detection_times[ip] = detection_time
                                detected_time_str = detection_time.strftime("%H:%M:%S.%f")[:-3]
                                self.gui_queue.put(('update_tree', ip, detected_time_str))
                                self.log(f"[INFO] IP {ip} rilevato alle {detected_time_str}")
                                if t0 is None:
                                    t0 = detection_time
                                else:
                                    elapsed_since_t0 = (detection_time - t0).total_seconds()
                                    if elapsed_since_t0 > self.config.timing.max_startup_delay:
                                        if ip not in current_cycle_defectives:
                                            self.log(f"[ALLARME] IP {ip} rilevato con ritardo di {elapsed_since_t0:.3f} secondi.")
                                            self.anomaly_count += 1
                                            self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
                                            current_cycle_defectives.add(ip)
            
                if all(self.detection_times[ip] is not None for ip in self.urls):
                    self.log("[INFO] Tutti gli IP hanno risposto.")
                    detection_sorted = sorted(self.detection_times.items(), key=lambda x: x[1])
                    ip_first, t_first = detection_sorted[0]
                    ip_last, t_last = detection_sorted[-1]
                    delay = (t_last - t_first).total_seconds()
                    self.save_cycle_report(ip_first, ip_last, delay)
                    break

                if t0:
                    elapsed_since_t0 = (datetime.datetime.now() - t0).total_seconds()
                    if elapsed_since_t0 > self.config.timing.max_startup_delay:
                        non_rilevati = [ip for ip in self.urls if self.detection_times[ip] is None]
                        if non_rilevati:
                            for ip in non_rilevati:
                                if ip not in current_cycle_defectives:
                                    self.log(f"[ALLARME] IP {ip} non ha risposto entro {self.config.timing.max_startup_delay} secondi.")
                                    self.gui_queue.put(('highlight_error', ip))
                                    self.anomaly_count += 1
                                    self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
                                    current_cycle_defectives.add(ip)
            
                if not self.wait_with_stop_check(self.config.timing.loop_check_period):
                    break

            if not self.run_test:
                break

            self.log("[INFO] Tutti gli IP hanno risposto. Attendo 5 secondi prima di spegnere l'alimentatore.")
            if not self.wait_with_stop_check(5):
                break

            self.log("[INFO] Spengo alimentatore (canali 1 e 2)...")
            try:
                for channel in (1, 2):
                    alimentatore.select_output(channel)
                    alimentatore.toggle_output(channel, 'OFF')
                self.log(f"[INFO] Attendo {self.config.timing.poweroff_delay} secondi durante lo spegnimento...")
                if not self.wait_with_stop_check(self.config.timing.poweroff_delay):
                    break
            except Exception as e:
                self.log(f"[ERRORE] Errore durante lo spegnimento: {str(e)}")
                continue

        if not self.test_stopped_intentionally:
            self.log("[INFO] Spegnimento finale dell'alimentatore...")
            try:
                for channel in (1, 2):
                    alimentatore.select_output(channel)
                    alimentatore.toggle_output(channel, 'OFF')
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
        if not self.report_file:
            self.log("[ERRORE] Nome del file di report non definito. Impossibile salvare il ciclo.")
            return
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cycle_str = f"{self.cycle_count:5d}"
        line = f"{now_str};\t{cycle_str};\t{ip_first};\t{ip_last};\t{delay:.3f}\n"
        try:
            with open(self.report_file, "a", encoding="utf-8") as f:
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
            try:
                self.cycle_start_count = int(self.entry_cycle_start.get())
            except ValueError:
                self.cycle_start_count = 0
                self.log("[ERRORE] Conteggio di partenza non valido. Impostato a 0.")
            self.cycle_count = self.cycle_start_count
            self.gui_queue.put(('update_label', 'cycle_count_label', f"Accensioni eseguite: {self.cycle_count}"))
            self.anomaly_count = 0
            self.gui_queue.put(('update_label', 'anomaly_count_label', "Accensioni con anomalia: 0"))
            self.report_file = self.make_report_filename()
            if self.report_file:
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
        """Mette in pausa o riprende il test."""
        if not hasattr(self, 'is_paused'):
            self.is_paused = False
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
            if not self.dp832_host:
                self.log("[ERRORE] IP alimentatore non configurato!")
                return
            alimentatore = dp832()
            self.log(f"[INFO] Connessione all'alimentatore {self.dp832_host}...")
            alimentatore.connect(self.dp832_host)
            for channel in (1, 2):
                alimentatore.select_output(channel)
                alimentatore.toggle_output(channel, 'ON')
            self.log("[INFO] Alimentatore forzato su ON.")
        except Exception as e:
            self.log(f"[ERRORE] Errore durante l'accensione forzata: {str(e)}")

    def force_power_off(self):
        """Forza manualmente lo spegnimento dell'alimentatore."""
        try:
            if not self.dp832_host:
                self.log("[ERRORE] IP alimentatore non configurato!")
                return
            alimentatore = dp832()
            self.log(f"[INFO] Connessione all'alimentatore {self.dp832_host}...")
            alimentatore.connect(self.dp832_host)
            for channel in (1, 2):
                alimentatore.select_output(channel)
                alimentatore.toggle_output(channel, 'OFF')
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
    config_path = sys.argv[1]
    config_path = os.path.join(os.getcwd(), config_path)
    config = TestBenchConfig.from_json(config_path)
    app = RigolTestApp(config)
    app.mainloop()
