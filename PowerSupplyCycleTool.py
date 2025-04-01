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

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Define di configurazione facilmente modificabile
DEFAULT_VERIFICATION_SUFFIX = ":9443"

# Sostituisci con la tua implementazione o libreria effettiva per l'alimentatore Rigol.
from dp832 import dp832

def data_from_csv(file_path: str):
    data: list[dict] = []
    with open(file_path, mode='r') as file:
        csv_reader = csv.DictReader(file, delimiter=';')
        data = [row['address'] for row in csv_reader]
    return data

def ip_to_int(ip_str):
    parts = ip_str.split(".")
    if len(parts) != 4:
        raise ValueError(f"IP non valido: {ip_str}")
    nums = [int(p) for p in parts]
    for n in nums:
        if n < 0 or n > 255:
            raise ValueError(f"Valore IP fuori range (0-255): {ip_str}")
    return (nums[0] << 24) + (nums[1] << 16) + (nums[2] << 8) + nums[3]

def int_to_ip(ip_int):
    if ip_int < 0 or ip_int > 0xFFFFFFFF:
        raise ValueError(f"IP int fuori range: {ip_int}")
    return ".".join([
        str((ip_int >> 24) & 0xFF),
        str((ip_int >> 16) & 0xFF),
        str((ip_int >> 8) & 0xFF),
        str(ip_int & 0xFF)
    ])

class RigolTestApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.geometry("1280x800")
        self.title("Rigol Test GUI")
        
        # Parametri di default
        self.default_alimentatore_ip = "192.168.60.96"
        self.default_range_start = "192.168.60.10"
        self.default_range_end   = "192.168.60.21"
        
        # Stringa di verifica configurabile (viene impostata tramite GUI)
        self.verification_suffix = DEFAULT_VERIFICATION_SUFFIX
        
        # Lista IP e tempi di rilevamento
        self.ip_addresses = []
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
        
        # Tempi di default
        self.TEMPO_PRE_CHECK   = 30
        self.TEMPO_CHECK_LOOP  = 0.1  # 100ms
        self.TEMPO_SPEGNIMENTO = 30
        self.max_startup_delay = 5
        
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




    def create_widgets(self):
        """
        Crea tutti i widget (label, entry, treeview, pulsanti) e li posiziona nella finestra principale.
        """
        # Configurazione della griglia principale
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(5, weight=1)  # l'area log

        # Frame 1: IP Alimentatore, Range IP e URL di verifica
        range_frame = ttk.LabelFrame(self, text="Alimentatore e Range IP")
        range_frame.grid(row=0, column=0, padx=10, pady=5, sticky="ew")

        range_frame.grid_columnconfigure(6, weight=1)

        # Riga 0: IP Alimentatore, IP Start e IP End
        ttk.Label(range_frame, text="IP Alimentatore:").grid(row=0, column=0, padx=5, pady=5)
        self.dp832_entry = ttk.Entry(range_frame, width=15)
        self.dp832_entry.insert(0, self.default_alimentatore_ip)
        self.dp832_entry.grid(row=0, column=1, padx=5)

        ttk.Label(range_frame, text="IP Start:").grid(row=0, column=2, padx=5)
        self.start_ip_entry = ttk.Entry(range_frame, width=15)
        self.start_ip_entry.insert(0, self.default_range_start)
        self.start_ip_entry.grid(row=0, column=3, padx=5)

        ttk.Label(range_frame, text="IP End:").grid(row=0, column=4, padx=5)
        self.end_ip_entry = ttk.Entry(range_frame, width=15)
        self.end_ip_entry.insert(0, self.default_range_end)
        self.end_ip_entry.grid(row=0, column=5, padx=5)

        # Riga 1: Campo per l'URL di verifica
        ttk.Label(range_frame, text="URL di verifica:").grid(row=1, column=0, padx=5, pady=5)
        self.verification_suffix_entry = ttk.Entry(range_frame, width=20)
        # Il valore predefinito è impostato dalla costante DEFAULT_VERIFICATION_SUFFIX
        self.verification_suffix_entry.insert(0, DEFAULT_VERIFICATION_SUFFIX)
        self.verification_suffix_entry.grid(row=1, column=1, padx=5, pady=5, columnspan=2, sticky="w")

        # Riga 2: Pulsante per applicare il range e la configurazione
        self.apply_button = ttk.Button(range_frame, text="Applica Range", command=self.apply_ip_range)
        self.apply_button.grid(row=2, column=0, columnspan=6, padx=5, pady=5)

        # Riga 3: Pulsante per importare una lista di indirizzi da un file di configurazione
        self.apply_button = ttk.Button(range_frame, text="Importa da file", command=self.retrieve_ip_list_from_config)
        self.apply_button.grid(row=3, column=0, columnspan=6, padx=5, pady=5)

        # Frame 2: Configurazione Tempi
        times_frame = ttk.LabelFrame(self, text="Configurazione Tempi (in secondi)")
        times_frame.grid(row=1, column=0, padx=10, pady=5, sticky="ew")

        times_frame.grid_columnconfigure(1, weight=1)

        labels_entries = [
            ("Attesa prima di controllare IP (Pre-check):", "entry_precheck", self.TEMPO_PRE_CHECK),
            ("Intervallo tra controlli IP:", "entry_checkloop", self.TEMPO_CHECK_LOOP),
            ("Durata spegnimento:", "entry_speg", self.TEMPO_SPEGNIMENTO),
            ("Massimo ritardo avvio dispositivi:", "entry_maxdelay", self.max_startup_delay),
            ("Conteggio di partenza:", "entry_cycle_start", 0)
        ]

        for idx, (label_text, entry_name, default_value) in enumerate(labels_entries):
            ttk.Label(times_frame, text=label_text).grid(row=idx, column=0, sticky="w", padx=5, pady=2)
            entry = ttk.Entry(times_frame, width=6)
            entry.insert(0, str(default_value))
            entry.grid(row=idx, column=1, sticky="w", padx=5, pady=2)
            setattr(self, entry_name, entry)

        self.btn_applica_tempi = ttk.Button(times_frame, text="Applica Impostazioni", 
                                            command=self.apply_time_settings)
        self.btn_applica_tempi.grid(row=len(labels_entries), column=0, columnspan=2, pady=5)

        # Frame 3: Info frame (timer, contatori)
        info_frame = ttk.Frame(self)
        info_frame.grid(row=2, column=0, padx=10, pady=5, sticky="ew")

        self.elapsed_time_label = ttk.Label(info_frame, text="Test non ancora partito.")
        self.elapsed_time_label.pack(side="left", padx=5)

        self.cycle_count_label = ttk.Label(info_frame, text="Accensioni eseguite: 0")
        self.cycle_count_label.pack(side="left", padx=20)

        self.anomaly_count_label = ttk.Label(info_frame, text="Accensioni con anomalia: 0")
        self.anomaly_count_label.pack(side="left", padx=20)

        # Frame 4: Controlli manuali
        manual_frame = ttk.LabelFrame(self, text="Controlli Manuali")
        manual_frame.grid(row=3, column=0, padx=10, pady=5, sticky="ew")

        manual_frame.grid_columnconfigure(3, weight=1)

        self.pause_button = ttk.Button(manual_frame, text="Pausa", command=self.toggle_pause)
        self.pause_button.grid(row=0, column=0, padx=5, pady=5)

        self.force_on_button = ttk.Button(manual_frame, text="Forza ON", command=self.force_power_on)
        self.force_on_button.grid(row=0, column=1, padx=5, pady=5)

        self.force_off_button = ttk.Button(manual_frame, text="Forza OFF", command=self.force_power_off)
        self.force_off_button.grid(row=0, column=2, padx=5, pady=5)

        self.pause_status_label = ttk.Label(manual_frame, text="Stato: In esecuzione")
        self.pause_status_label.grid(row=0, column=3, padx=5, pady=5, sticky="w")

        # Frame 5: Tabella IP
        table_frame = ttk.Frame(self)
        table_frame.grid(row=4, column=0, padx=10, pady=5, sticky="ew")

        ttk.Label(table_frame, text="Stato IP (Mostra orario di rilevamento):").pack(anchor="w")

        columns = ("ip", "detected")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings")
        self.tree.heading("ip", text="Indirizzo IP")
        self.tree.heading("detected", text="Rilevato alle (HH:MM:SS)")
        self.tree.column("ip", width=200)
        self.tree.column("detected", width=300)

        # Definizione dei tag per la Treeview
        self.tree.tag_configure('error', foreground='red')
        self.tree.tag_configure('normal', foreground='black')

        self.tree.pack(fill="x")

        # Frame 6: Controlli e Log
        controls_frame = ttk.Frame(self)
        controls_frame.grid(row=5, column=0, padx=10, pady=5, sticky="nsew")

        controls_frame.grid_columnconfigure(0, weight=1)
        controls_frame.grid_rowconfigure(1, weight=1)

        # Pulsanti Start/Stop
        button_frame = ttk.Frame(controls_frame)
        button_frame.grid(row=0, column=0, sticky="ew")

        self.start_button = ttk.Button(button_frame, text="Start", command=self.start_test)
        self.start_button.pack(side="left", padx=5)

        self.stop_button = ttk.Button(button_frame, text="Stop", command=self.stop_test)
        self.stop_button.pack(side="left", padx=5)

        # Area Log
        ttk.Label(controls_frame, text="Log:").grid(row=1, column=0, sticky="w")
        self.log_text = scrolledtext.ScrolledText(controls_frame, wrap=tk.WORD)
        self.log_text.grid(row=2, column=0, sticky="nsew")








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

    def ip_responds_curl(self, ip):
        """Verifica se l'IP risponde utilizzando curl e la stringa di verifica configurata."""
        protocol = "http" if self.verification_suffix.startswith(":80") else "https"
        url = f"{protocol}://{ip}{self.verification_suffix}"
        try:
            result = subprocess.run(
                ['curl', '-k', '-s', '-o', '/dev/null', '-w', '%{http_code}', url],
                timeout=3,
                capture_output=True,
                text=True
            )
            return result.stdout.strip() == '200'
        except subprocess.TimeoutExpired:
            self.log(f"[DEBUG] IP {ip} non risponde: Timeout")
            return False
        except Exception as e:
            self.log(f"[DEBUG] IP {ip} verifica fallita: {e}")
            return False
    
    def retrieve_ip_list_from_config(self):
        filepath = sys.argv[1]
        filepath = os.path.join(os.getcwd(), filepath)
        data = data_from_csv(filepath)
        for entry in data:
            self.ip_addresses.append(entry)
            self.log(f"[INFO] IP found: {entry}")

    def apply_ip_range(self):
        """
        Applica il range IP e la configurazione dell'URL di verifica inseriti dall'utente.
        """
        self.dp832_host = self.dp832_entry.get().strip()
        start_str = self.start_ip_entry.get().strip()
        end_str   = self.end_ip_entry.get().strip()
        # Aggiorna la stringa di verifica dall'apposito campo
        self.verification_suffix = self.verification_suffix_entry.get().strip()
        if not self.verification_suffix:
            self.verification_suffix = DEFAULT_VERIFICATION_SUFFIX

        try:
            start_val = ip_to_int(start_str)
            end_val   = ip_to_int(end_str)
        except ValueError as ve:
            self.log(f"[ERRORE] {ve}")
            return
        
        if start_val > end_val:
            self.log("[ERRORE] IP Start deve essere <= IP End.")
            return
        
        # Pulisce la Treeview
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Ricrea la lista degli IP
        self.ip_addresses = []
        for ip_int in range(start_val, end_val + 1):
            ip_str = int_to_ip(ip_int)
            self.ip_addresses.append(ip_str)
        
        # Resetta i tempi di rilevamento
        self.detection_times.clear()
        for ip in self.ip_addresses:
            self.detection_times[ip] = None
            self.tree.insert("", tk.END, iid=ip, values=(ip, ""), tags=('normal',))
        
        rows_to_show = min(len(self.ip_addresses), 30)
        self.tree.config(height=rows_to_show)

        self.log(f"[INFO] Impostato IP Alimentatore: {self.dp832_host}")
        self.log(f"[INFO] Range IP: {start_str} -> {end_str} (tot: {len(self.ip_addresses)})")
        self.log(f"[INFO] URL di verifica impostato a: {self.verification_suffix}")

    def apply_time_settings(self):
        """
        Applica i tempi configurati dall'utente.
        """
        try:
            self.TEMPO_PRE_CHECK   = int(self.entry_precheck.get())
            self.TEMPO_CHECK_LOOP  = float(self.entry_checkloop.get())
            self.TEMPO_SPEGNIMENTO = int(self.entry_speg.get())
            self.max_startup_delay = int(self.entry_maxdelay.get())
            self.cycle_start_count = int(self.entry_cycle_start.get())
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
            
            for ip in self.ip_addresses:
                self.detection_times[ip] = None
                self.gui_queue.put(('update_tree', ip, ""))
                self.gui_queue.put(('remove_tag', ip))
            
            self.log(f"[INFO] Attendo {self.TEMPO_PRE_CHECK} secondi prima del controllo degli IP.")
            if not self.wait_with_stop_check(self.TEMPO_PRE_CHECK):
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
                    future_to_ip = {executor.submit(self.ip_responds_curl, ip): ip for ip in self.ip_addresses if self.detection_times[ip] is None}
                    
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
                                    if elapsed_since_t0 > self.max_startup_delay:
                                        if ip not in current_cycle_defectives:
                                            self.log(f"[ALLARME] IP {ip} rilevato con ritardo di {elapsed_since_t0:.3f} secondi.")
                                            self.anomaly_count += 1
                                            self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
                                            current_cycle_defectives.add(ip)
            
                if all(self.detection_times[ip] is not None for ip in self.ip_addresses):
                    self.log("[INFO] Tutti gli IP hanno risposto.")
                    detection_sorted = sorted(self.detection_times.items(), key=lambda x: x[1])
                    ip_first, t_first = detection_sorted[0]
                    ip_last, t_last = detection_sorted[-1]
                    delay = (t_last - t_first).total_seconds()
                    self.save_cycle_report(ip_first, ip_last, delay)
                    break

                if t0:
                    elapsed_since_t0 = (datetime.datetime.now() - t0).total_seconds()
                    if elapsed_since_t0 > self.max_startup_delay:
                        non_rilevati = [ip for ip in self.ip_addresses if self.detection_times[ip] is None]
                        if non_rilevati:
                            for ip in non_rilevati:
                                if ip not in current_cycle_defectives:
                                    self.log(f"[ALLARME] IP {ip} non ha risposto entro {self.max_startup_delay} secondi.")
                                    self.gui_queue.put(('highlight_error', ip))
                                    self.anomaly_count += 1
                                    self.gui_queue.put(('update_label', 'anomaly_count_label', f"Accensioni con anomalia: {self.anomaly_count}"))
                                    current_cycle_defectives.add(ip)
            
                if not self.wait_with_stop_check(self.TEMPO_CHECK_LOOP):
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
                self.log(f"[INFO] Attendo {self.TEMPO_SPEGNIMENTO} secondi durante lo spegnimento...")
                if not self.wait_with_stop_check(self.TEMPO_SPEGNIMENTO):
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
                self.log(f"[INFO] Attendo {self.TEMPO_SPEGNIMENTO} secondi durante lo spegnimento finale...")
                time.sleep(self.TEMPO_SPEGNIMENTO)
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
        steps = int(seconds / self.TEMPO_CHECK_LOOP)
        for _ in range(steps):
            if not self.run_test:
                return False
            time.sleep(self.TEMPO_CHECK_LOOP)
        return True

# Avvio dell'applicazione
if __name__ == "__main__":
    app = RigolTestApp()
    app.mainloop()
