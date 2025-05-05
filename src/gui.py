import datetime
from enum import Enum
import tkinter as tk
from tkinter import ttk, scrolledtext
from typing import Callable, Optional

PADX_DEFAULT = 2
PADY_DEFAULT = 2

class ModbusFrame(tk.LabelFrame):
    modbus_enable_automatic_cycle_count_var: tk.IntVar
    modbus_register_address_var: tk.IntVar
    modbus_register_value_var: tk.IntVar
    modbus_enable_change_cb: Callable[[bool], None] | None = None
    modbus_register_address_change_cb: Callable[[int], None] | None = None
    modbus_register_value_change_cb: Callable[[int], None] | None = None
    
    reset_cycle_count_press_cb: Callable[[], None] | None = None
    reset_time_count_press_cb: Callable[[], None] | None = None
    read_register_press_cb: Callable[[], None] | None = None
    write_register_press_cb: Callable[[], None] | None = None
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="MODBUS")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        
        self.modbus_enable_automatic_cycle_count_var = tk.IntVar(self)
        modbus_enable_checkbutton = tk.Checkbutton(self, text='Enable automatic cycle count check',variable=self.modbus_enable_automatic_cycle_count_var, command=self.on_modbus_enable_change)
        modbus_enable_checkbutton.grid(row=0, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        # ROW1 - register frame
        register_frame = tk.Frame(self)
        register_frame.grid(row=1, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        modbus_register_address_label = tk.Label(register_frame, text="Register address")
        modbus_register_address_label.grid(row=0, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        self.modbus_register_address_var = tk.IntVar()
        self.modbus_register_address_var.trace_add("write", self.on_register_address_change)
        modbus_register_address_entry = tk.Entry(register_frame, textvariable=self.modbus_register_address_var)
        modbus_register_address_entry.grid(row=0, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ne")
        
        register_value_label = tk.Label(register_frame, text="Register value")
        register_value_label.grid(row=1, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        self.modbus_register_value_var = tk.IntVar()
        self.modbus_register_value_var.trace_add("write", self.on_register_value_change)
        modbus_register_value_entry = tk.Entry(register_frame, textvariable=self.modbus_register_value_var)
        modbus_register_value_entry.grid(row=1, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="new")
        
        # ROW2 - buttons frame
        buttons_frame = tk.Frame(self)
        buttons_frame.grid(row=2, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        modbus_read_register_button = tk.Button(buttons_frame, text="Read", command=self.on_read_register_press)
        modbus_read_register_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        force_write_button = tk.Button(buttons_frame, text="Write", command=self.on_write_register_press)
        force_write_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        
        reset_cycle_count_button = tk.Button(buttons_frame, text="Reset cycle count", command=self.on_reset_cycle_count_press)
        reset_cycle_count_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        
        reset_time_count_button = tk.Button(buttons_frame, text="Reset time count", command=self.on_reset_time_count_press)
        reset_time_count_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
    
    def set_modbus_enable(self, value: bool):
        value = int(value)
        self.modbus_enable_automatic_cycle_count_var.set(value)
    
    def set_register_address(self, value: int):
        self.modbus_register_address_var.set(value)
    
    def set_register_value(self, value: int):
        self.modbus_register_value_var.set(value)
    
    def set_modbus_enable_change_cb(self, cb: Callable[[bool], None]):
        self.modbus_enable_change_cb = cb
        
    def set_register_address_change_cb(self, cb: Callable[[int], None]):
        self.modbus_register_address_change_cb = cb
    
    def set_register_value_change_cb(self, cb: Callable[[int], None]):
        self.modbus_register_value_change_cb = cb
    
    def set_reset_cycle_count_press_cb(self, cb: Callable[[], None]):
        self.reset_cycle_count_press_cb = cb
    
    def set_reset_time_count_press_cb(self, cb: Callable[[], None]):
        self.reset_time_count_press_cb = cb
    
    def set_read_register_press_cb(self, cb: Callable[[], None]):
        self.read_register_press_cb = cb
    
    def set_write_register_press_cb(self, cb: Callable[[], None]):
        self.write_register_press_cb = cb
    
    def on_modbus_enable_change(self, *args):
        if self.modbus_enable_change_cb is not None:
            value = self.modbus_enable_automatic_cycle_count_var.get()
            value = value == 1
            self.modbus_enable_change_cb(value)
    
    def on_register_address_change(self, *args):
        if self.modbus_register_address_change_cb is not None:
            try:
                value = self.modbus_register_address_var.get()
                self.modbus_register_address_change_cb(value)
            except:
                pass
    
    def on_register_value_change(self, *args):
        if self.modbus_register_value_change_cb is not None:
            try:
                value = self.modbus_register_value_var.get()
                self.modbus_register_value_change_cb(value)
            except:
                pass
    
    def on_reset_cycle_count_press(self):
        if self.reset_cycle_count_press_cb is not None:
            self.reset_cycle_count_press_cb()
    
    def on_reset_time_count_press(self):
        if self.reset_time_count_press_cb is not None:
            self.reset_time_count_press_cb()
    
    def on_read_register_press(self):
        if self.read_register_press_cb is not None:
            self.read_register_press_cb()
    
    def on_write_register_press(self):
        if self.write_register_press_cb is not None:
            self.write_register_press_cb()

class SSHFrame(tk.LabelFrame):
    ssh_enabled_var: tk.IntVar
    username_var: tk.StringVar
    password_var: tk.StringVar
    command_var: tk.StringVar
    
    username_change_cb: Callable[[str], None] | None = None
    password_change_cb: Callable[[str], None] | None = None
    command_change_cb: Callable[[str], None] | None = None
    ssh_enabled_change_cb: Callable[[bool], None] | None = None
    
    def __init__(self, parent, row, col, padx, pady, sticky): 
        super().__init__(parent, text="SSH")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        
        self.ssh_enabled_var = tk.IntVar(self)
        
        ssh_enabled_checkbutton = tk.Checkbutton(self, text='Run SSH command on power-off',variable=self.ssh_enabled_var, command=self.on_ssh_enabled_change)
        ssh_enabled_checkbutton.grid(row=0, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        # credentials frame
        credentials_frame = tk.Frame(self)
        credentials_frame.grid(row=1, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        # username
        username_label = tk.Label(credentials_frame, text="Username")
        username_label.grid(row=0, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        self.username_var = tk.StringVar(credentials_frame)
        self.username_var.trace_add("write", self.on_username_change)
        username = tk.Entry(credentials_frame, width=40, textvariable=self.username_var)
        username.grid(row=0, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ne")
        
        # password
        password_label = tk.Label(credentials_frame, text="Password")
        password_label.grid(row=1, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        self.password_var = tk.StringVar(credentials_frame)
        self.password_var.trace_add("write", self.on_password_change)
        password = tk.Entry(credentials_frame, width=40, textvariable=self.password_var)
        password.grid(row=1, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ne")
        
        # command
        command_label = tk.Label(credentials_frame, text="Command")
        command_label.grid(row=2, column=0, sticky="w", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
        self.command_var = tk.StringVar(credentials_frame)
        self.command_var.trace_add("write", self.on_command_change)
        command = tk.Entry(credentials_frame, width=40, textvariable=self.command_var)
        command.grid(row=2, column=1, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="ne")
    
    def set_ssh_enabled(self, value: bool):
        value = int(value)
        self.ssh_enabled_var.set(value)
    
    def set_username(self, value: str):
        self.username_var.set(value)

    def set_password(self, value: str):
        self.password_var.set(value)

    def set_command(self, value: str):
        self.command_var.set(value)
    
    def set_username_change_cb(self, cb: Callable[[str], None]):
        self.username_change_cb = cb
        
    def set_password_change_cb(self, cb: Callable[[str], None]):
        self.password_change_cb = cb
    
    def set_command_change_cb(self, cb: Callable[[str], None]):
        self.command_change_cb = cb
    
    def set_ssh_enabled_change_cb(self, cb: Callable[[bool], None]):
        self.ssh_enabled_change_cb = cb
    
    def on_ssh_enabled_change(self, *args):
        if self.ssh_enabled_change_cb is not None:
            value = self.ssh_enabled_var.get()
            value = value == 1
            self.ssh_enabled_change_cb(value)
        
    def on_username_change(self, *args):
        if self.username_change_cb is not None:
            value = self.username_var.get()
            self.username_change_cb(value)
        
    def on_password_change(self, *args):
        if self.password_change_cb is not None:
            value = self.password_var.get()
            self.password_change_cb(value)
        
    def on_command_change(self, *args):
        if self.command_change_cb is not None:
            value = self.command_var.get()
            self.command_change_cb(value)
    
class TimingFrame(tk.LabelFrame):
    precheck_var: tk.DoubleVar
    checkloop_var: tk.DoubleVar
    speg_var: tk.DoubleVar
    maxdelay_var: tk.DoubleVar
    cycle_start_var: tk.IntVar
    precheck_change_cb: Callable[[float], None] | None = None
    checkloop_change_cb: Callable[[float], None] | None = None
    speg_change_cb: Callable[[float], None] | None = None
    maxdelay_change_cb: Callable[[float], None] | None = None
    cycle_start_change_cb: Callable[[int], None] | None = None
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Timing")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        labels_entries = [
            ("Attesa prima di controllare IP (Pre-check):", "precheck", "float"),
            ("Intervallo tra controlli IP:", "checkloop", "float"),
            ("Durata spegnimento:", "speg", "float"),
            ("Massimo ritardo avvio dispositivi:", "maxdelay", "float"),
            ("Conteggio di partenza:", "cycle_start", "int")
        ]

        for idx, (label_text, entry_name, data_type) in enumerate(labels_entries):
            label = tk.Label(self, text=label_text)
            label.grid(row=idx, column=0, sticky="nw", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            
            entry_var = None
            match data_type:
                case "float":
                    entry_var = tk.DoubleVar(self)
                case "int":
                    entry_var = tk.IntVar(self)
                case _:
                    pass
            
            if entry_var is None:
                continue
            
            callback_name = f"on_{entry_name}_change"
            callback = getattr(self, callback_name)
            entry_var.trace_add("write", callback)

            setattr(self, f"{entry_name}_var", entry_var)
            entry = tk.Entry(self, textvariable=entry_var)
            entry.grid(row=idx, column=1, sticky="ne", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
            setattr(self, entry_name, entry)
    
    def set_precheck(self, value: float):
        self.precheck_var.set(value)
    
    def set_checkloop(self, value: float):
        self.checkloop_var.set(value)
    
    def set_speg(self, value: float):
        self.speg_var.set(value)
    
    def set_maxdelay(self, value: float):
        self.maxdelay_var.set(value)
    
    def set_cycle_start(self, value: int):
        self.cycle_start_var.set(value)
    
    def set_precheck_cb(self, cb: Callable[[float], None]):
        self.precheck_change_cb = cb

    def set_checkloop_cb(self, cb: Callable[[float], None]):
        self.checkloop_change_cb = cb

    def set_speg_cb(self, cb: Callable[[float], None]):
        self.speg_change_cb = cb

    def set_maxdelay_cb(self, cb: Callable[[float], None]):
        self.maxdelay_change_cb = cb

    def set_cycle_start_cb(self, cb: Callable[[int], None]):
        self.cycle_start_change_cb = cb

    def on_precheck_change(self, *args):
        if self.precheck_change_cb is not None:
            try:
                value = self.precheck_var.get()
                self.precheck_change_cb(value)
            except:
                pass
        
    def on_checkloop_change(self, *args):
        if self.checkloop_change_cb is not None:
            try:
                value = self.checkloop_var.get()
                self.checkloop_change_cb(value)
            except:
                pass
    def on_speg_change(self, *args):
        if self.speg_change_cb is not None:
            try:
                value = self.speg_var.get()
                self.speg_change_cb(value)
            except:
                pass
    def on_cycle_start_change(self, *args):
        if self.cycle_start_change_cb is not None:
            try:
                value = self.cycle_start_var.get()
                self.cycle_start_change_cb(value)
            except:
                pass
    
    def on_maxdelay_change(self, *args):
        if self.maxdelay_change_cb is not None:
            try:
                value = self.maxdelay_var.get()
                self.maxdelay_change_cb(value)
            except:
                pass

class PsuFrame(tk.LabelFrame):
    psu_ip_var: tk.StringVar
    psu_enabled_var: tk.IntVar
    psu_ip_change_cb: Callable[[str], None] | None = None
    psu_enabled_change_cb: Callable[[bool], None] | None = None
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="PSU")
        # Frame 1: IP Alimentatore, Range IP e URL di verifica
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        # Riga 1: use remote PSU
        self.psu_enabled_var = tk.IntVar(self)
        psu_enabled_checkbutton = tk.Checkbutton(self, text='Use remote PSU',variable=self.psu_enabled_var, command=self.on_psu_enable_change)
        psu_enabled_checkbutton.grid(row=0, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        # Riga 0: IP Alimentatore, IP Start e IP End
        psu_ip_label = tk.Label(self, text="IP Alimentatore:")
        psu_ip_label.grid(row=1, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky="nw")
        
        self.psu_ip_var = tk.StringVar(self)
        self.psu_ip_var.trace_add("write", self.on_psu_ip_change)
        self.psu_ip = tk.Entry(self, textvariable=self.psu_ip_var)
        self.psu_ip.grid(row=1, column=1, sticky="ne")
    
    def set_psu_ip(self, value: str):
        self.psu_ip_var.set(value)
    
    def set_psu_enabled(self, value: bool):
        value = int(value)
        self.psu_enabled_var.set(value)
    
    def set_psu_ip_change_cb(self, cb: Callable[[str], None]):
        self.psu_ip_change_cb = cb
    
    def set_psu_enabled_change_cb(self, cb: Callable[[str], None]):
        self.psu_enabled_change_cb = cb
    
    def on_psu_ip_change(self, *args):
        if self.psu_ip_change_cb is not None:
            value = self.psu_ip_var.get()
            self.psu_ip_change_cb(value)

    def on_psu_enable_change(self, *args):
        if self.psu_enabled_change_cb is not None:
            value = self.psu_enabled_var.get()
            value = value == 1
            self.psu_enabled_change_cb(value)

class ManualControlsFrame(tk.LabelFrame):
    pause_button: tk.Button
    pause_status_label: tk.Label
    start_button_press_cb: Callable[[], None] | None = None
    stop_button_press_cb: Callable[[], None] | None = None
    pause_button_press_cb: Callable[[], None] | None = None
    force_on_button_press_cb: Callable[[], None] | None = None
    force_off_button_press_cb: Callable[[], None] | None = None
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Controlli Manuali")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        start_button = tk.Button(self, text="Start", command=self.on_start_button_press)
        start_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        stop_button = tk.Button(self, text="Stop", command=self.on_stop_button_press)
        stop_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        self.pause_button = tk.Button(self, text="Pausa", command=self.on_pause_button_press)
        self.pause_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        force_on_button = tk.Button(self, text="Forza ON", command=self.on_force_poweron_button_press)
        force_on_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        force_off_button = tk.Button(self, text="Forza OFF", command=self.on_force_poweronff_button_press)
        force_off_button.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)

        self.pause_status_label = tk.Label(self, text="Stato: In esecuzione")
        self.pause_status_label.pack(side="left", padx=PADX_DEFAULT, pady=PADY_DEFAULT)
    
    def set_pause_button_text(self, content: str):
        self.pause_button.configure(text=content)
    
    def set_pause_status_label(self, content: str):
        self.pause_status_label.configure(text=content)
    
    def set_start_button_press_cb(self, cb: Callable[[], None]):
        self.start_button_press_cb = cb
   
    def set_stop_button_press_cb(self, cb: Callable[[], None]):
        self.stop_button_press_cb = cb
   
    def set_pause_button_press_cb(self, cb: Callable[[], None]):
        self.pause_button_press_cb = cb
   
    def set_force_on_button_press_cb(self, cb: Callable[[], None]):
        self.force_on_button_press_cb = cb
   
    def set_force_off_button_press_cb(self, cb: Callable[[], None]):
        self.force_off_button_press_cb = cb
    
    def on_start_button_press(self):
        if self.start_button_press_cb is not None:
            self.start_button_press_cb()
    
    def on_stop_button_press(self):
        if self.stop_button_press_cb is not None:
            self.stop_button_press_cb()
    
    def on_pause_button_press(self):
        if self.pause_button_press_cb is not None:
            self.pause_button_press_cb()
    
    def on_force_poweron_button_press(self):
        if self.force_on_button_press_cb is not None:
            self.force_on_button_press_cb()
    
    def on_force_poweronff_button_press(self):
        if self.force_off_button_press_cb is not None:
            self.force_off_button_press_cb()

class InfoFrame(tk.LabelFrame):
    elapsed_time_label: tk.Label
    time_to_next_state: tk.Label
    cycle_count_label: tk.Label
    anomaly_count_label: tk.Label
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Info")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        
        counters_frame = tk.Frame(self)
        counters_frame.grid(row=0, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky=sticky)

        self.cycle_count_label = tk.Label(counters_frame, text="Accensioni eseguite: 0")
        self.cycle_count_label.pack(side="left", padx=5)
        
        self.anomaly_count_label = tk.Label(counters_frame, text="Accensioni con anomalia: 0")
        self.anomaly_count_label.pack(side="left", padx=5)
        
        times_frame = tk.Frame(self)
        times_frame.grid(row=1, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT, sticky=sticky)
        
        self.elapsed_time_label = tk.Label(times_frame, text="Test non ancora partito.")
        self.elapsed_time_label.pack(side="left", padx=5)
        
        self.time_to_next_state = tk.Label(times_frame, text="Time to next state")
        self.time_to_next_state.pack(side="left", padx=5)
    
    def set_elapsed_time_label(self, value: str):
        self.elapsed_time_label.configure(text=value)
    
    def set_time_to_next_state(self, value: str):
        self.time_to_next_state.configure(text=value)
    
    def set_cycle_count_label(self, value: str):
        self.cycle_count_label.configure(text=value)
    
    def set_anomaly_count_label(self, value: str):
        self.anomaly_count_label.configure(text=value)

class IpTableFrame(tk.LabelFrame):
    tree: ttk.Treeview
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="IP table")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        columns = ("ip", "detected")
        self.tree = ttk.Treeview(self, columns=columns, show="headings")
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
        vsb = tk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        vsb.pack(side='right', fill='y')

        self.tree.configure(yscrollcommand=vsb.set)
    
    def tree_clear(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
    
    def tree_set(self, ip: str, label: str, time: str):
        self.tree.set(ip, label, time)
    
    def tree_item(self, ip: str, tags):
        self.tree.item(ip, tags=tags)
    
    def tree_insert(self, ip: str, values, tags):
        self.tree.insert("", tk.END, iid=ip, values=values, tags=tags)

class FileFrame(tk.LabelFrame):
    file: scrolledtext.ScrolledText
    apply_button_press_cb: Callable[[], None] | None = None
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="File")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        
        self.file = scrolledtext.ScrolledText(self, width=50)
        self.file.grid(row=0, column=0, sticky="nsew")
        self.file.config(height=17)

        apply_button = ttk.Button(self, text="Apply", command=self.on_apply_button_press)
        apply_button.grid(row=1, column=0, padx=PADX_DEFAULT, pady=PADY_DEFAULT)
    
    def set_apply_button_press_cb(self, cb: Callable[[], None]):
        self.apply_button_press_cb = cb
    
    def on_apply_button_press(self):
        if self.apply_button_press_cb is not None:
            self.apply_button_press_cb()
    
    def load_text(self, content: str):
        self.file.insert('1.0', content)
    
    def get_text(self):
        return self.file.get("1.0", "end-1c")

class LogType(Enum):
    Error = "error"
    Warn = "warning"
    Info = "info"

class LogFrame(tk.LabelFrame):
    log_text: scrolledtext.ScrolledText
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Log")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        self.log_text = scrolledtext.ScrolledText(self, wrap=tk.WORD, width=65)
        self.log_text.grid(row=0, column=0, sticky="nsew")
        self.log_text.config(height=23)
        self.log_text.tag_configure(LogType.Error.value, foreground="red")
        self.log_text.tag_configure(LogType.Warn.value, foreground="orange")
        self.log_text.tag_configure(LogType.Info.value, foreground="black")
        self.log_text.config(state=tk.DISABLED)
    
    def add_log(self, msg: str, type: LogType, timestamp: Optional[datetime.datetime]):
        message = ""
        if timestamp is not None:
            now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            message += f"[{now_str}]"
        message += f"{msg}\n"
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message, type.value)
        self.log_text.config(state=tk.DISABLED)
    
    def scroll_down(self):
        self.log_text.see(tk.END)