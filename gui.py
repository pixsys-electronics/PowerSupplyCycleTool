import tkinter as tk
from tkinter import ttk

class ModbusFrame(tk.LabelFrame):
    modbus_enable_var: tk.IntVar
    modbus_register_address_var: tk.StringVar
    modbus_register_value_var: tk.StringVar
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="MODBUS")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        
        self.modbus_enable_var = tk.IntVar(self, value=False)
        modbus_enable_checkbutton = tk.Checkbutton(self, text='Enable automatic cycle count check',variable=self.modbus_enable_var, command=self.on_modbus_enable_change)
        modbus_enable_checkbutton.grid(row=0, column=0, padx=0, pady=0, sticky="nw")
        
        # ROW1 - register frame
        register_frame = tk.Frame(self)
        register_frame.grid(row=1, column=0, padx=0, pady=0, sticky="nw")
        
        modbus_register_address_label = tk.Label(register_frame, text="Register address")
        modbus_register_address_label.grid(row=0, column=0, padx=0, pady=0, sticky="nw")
        self.modbus_register_address_var = tk.StringVar()
        modbus_register_address_entry = tk.Entry(register_frame, width=20, textvariable=self.modbus_register_address_var)
        modbus_register_address_entry.grid(row=0, column=1, padx=0, pady=0, sticky="nw")
        
        register_value_label = tk.Label(register_frame, text="Register value")
        register_value_label.grid(row=1, column=0, padx=0, pady=0, sticky="nw")
        self.modbus_register_value_var = tk.StringVar()
        modbus_register_value_entry = tk.Entry(register_frame, width=20, textvariable=self.modbus_register_value_var)
        modbus_register_value_entry.grid(row=1, column=1, padx=0, pady=0, sticky="nw")
        
        # ROW2 - buttons frame
        buttons_frame = tk.Frame(self)
        buttons_frame.grid(row=2, column=0, padx=0, pady=0, sticky="nw")
        
        modbus_read_register_button = tk.Button(buttons_frame, text="Read", command=self.on_force_poweron_press)
        modbus_read_register_button.pack(side="left", padx=0, pady=0)

        force_write_button = tk.Button(buttons_frame, text="Write", command=self.on_force_poweroff_press)
        force_write_button.pack(side="left", padx=0, pady=0)
        
        reset_cycle_count_button = tk.Button(buttons_frame, text="Reset cycle count", command=self.on_reset_cycle_count_press)
        reset_cycle_count_button.pack(side="left", padx=0, pady=0)
        
        reset_time_count_button = tk.Button(buttons_frame, text="Reset time count", command=self.on_reset_time_count_press)
        reset_time_count_button.pack(side="left", padx=0, pady=0)
    
    
    def on_modbus_enable_change(self, *args):
        pass
    
    def on_reset_cycle_count_press(self):
        pass
    
    def on_reset_time_count_press(self):
        pass
    
    def on_force_poweron_press(self):
        pass
    
    def on_force_poweroff_press(self):
        pass

class SSHFrame(tk.LabelFrame):
    ssh_enabled_var: tk.IntVar
    username_var: tk.StringVar
    password_var: tk.StringVar
    command_var: tk.StringVar
    
    def __init__(self, parent, row, col, padx, pady, sticky): 
        super().__init__(parent, text="SSH")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)
        
        self.ssh_enabled_var = tk.IntVar(self, value=False)
        
        ssh_enabled_checkbutton = tk.Checkbutton(self, text='Run SSH command on power-off',variable=self.ssh_enabled_var, command=self.on_ssh_enabled_change)
        ssh_enabled_checkbutton.grid(row=0, column=0, padx=0, pady=0, sticky="nw")
        
        # credentials frame
        credentials_frame = tk.Frame(self)
        credentials_frame.grid(row=1, column=0, padx=0, pady=0, sticky="nw")
        
        # username
        username_label = tk.Label(credentials_frame, text="Username")
        username_label.grid(row=0, column=0, padx=0, pady=0, sticky="nw")
        self.username_var = tk.StringVar(credentials_frame)
        self.username_var.trace_add("write", self.on_username_change)
        username = tk.Entry(credentials_frame, width=20, textvariable=self.username_var)
        username.grid(row=0, column=1, padx=0, pady=0, sticky="nw")
        
        # password
        password_label = tk.Label(credentials_frame, text="Password")
        password_label.grid(row=1, column=0, sticky="w", padx=0, pady=0)
        self.password_var = tk.StringVar(credentials_frame)
        self.password_var.trace_add("write", self.on_password_change)
        password = tk.Entry(credentials_frame, width=20, textvariable=self.password_var)
        password.grid(row=1, column=1, padx=0, pady=0, sticky="nw")
        
        # command
        command_label = tk.Label(credentials_frame, text="Command")
        command_label.grid(row=2, column=0, sticky="w", padx=0, pady=0)
        self.command_var = tk.StringVar(credentials_frame)
        self.command_var.trace_add("write", self.on_command_change)
        command = tk.Entry(credentials_frame, width=20, textvariable=self.command_var)
        command.grid(row=2, column=1, padx=0, pady=0, sticky="nw")
    
    def on_ssh_enabled_change(self, *args):
        pass
    
    def on_username_change(self, *args):
        pass
    
    def on_password_change(self, *args):
        pass
    
    def on_command_change(self, *args):
        pass

class TimingFrame(tk.LabelFrame):
    entry_precheck_var: tk.DoubleVar
    entry_checkloop_var: tk.DoubleVar
    entry_spegn_var: tk.DoubleVar
    entry_maxdelay_var: tk.DoubleVar
    entry_cycle_start_var: tk.IntVar
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Timing")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        labels_entries = [
            ("Attesa prima di controllare IP (Pre-check):", "entry_precheck"),
            ("Intervallo tra controlli IP:", "entry_checkloop"),
            ("Durata spegnimento:", "entry_speg"),
            ("Massimo ritardo avvio dispositivi:", "entry_maxdelay"),
            ("Conteggio di partenza:", "entry_cycle_start")
        ]

        for idx, (label_text, entry_name) in enumerate(labels_entries):
            label = tk.Label(self, text=label_text)
            label.grid(row=idx, column=0, sticky="w", padx=0, pady=0)
            
            entry_var = tk.IntVar(self)
            callback_name = f"on_{entry_name}_change"
            callback = getattr(self, callback_name)
            entry_var.trace_add("write", callback)

            setattr(self, f"{entry_name}_var", entry_var)
            entry = tk.Entry(self, width=6, textvariable=entry_var)
            entry.grid(row=idx, column=1, sticky="w", padx=0, pady=0)
            setattr(self, entry_name, entry)
    
    def on_entry_precheck_change(self, *args):
        pass
        
    def on_entry_checkloop_change(self, *args):
        pass        
    
    def on_entry_speg_change(self, *args):
        pass    
    
    def on_entry_cycle_start_change(self, *args):
        pass    
        
    def on_entry_maxdelay_change(self, *args):
        pass    

class PsuFrame(tk.LabelFrame):
    psu_ip_var: tk.StringVar
    psu_enabled_var: tk.IntVar
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="PSU")
        # Frame 1: IP Alimentatore, Range IP e URL di verifica
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        # Riga 0: IP Alimentatore, IP Start e IP End
        psu_ip_label = tk.Label(self, text="IP Alimentatore:")
        psu_ip_label.grid(row=0, column=0, padx=0, pady=0)
        
        self.psu_ip_var = tk.StringVar(self)
        self.psu_ip_var.trace_add("write", self.on_psu_ip_change)
        self.psu_ip = tk.Entry(self, width=15, textvariable=self.psu_ip_var)
        self.psu_ip.grid(row=0, column=1, padx=0)
        
        # Riga 1: use remote PSU
        self.psu_enabled = tk.IntVar(self)
        psu_enabled_checkbutton = tk.Checkbutton(self, text='Use remote PSU',variable=self.psu_enabled, command=self.on_psu_enable_change)
        psu_enabled_checkbutton.grid(row=1, column=0, padx=0, pady=0, sticky="nw")
    
    def on_psu_ip_change(self, *args):
        pass

    def on_psu_enable_change(self, *args):
        pass

class ManualControlsFrame(tk.LabelFrame):
    
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Controlli Manuali")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        self.start_button = tk.Button(self, text="Start", command=self.on_start_button_press)
        self.start_button.pack(side="left", padx=0, pady=0)

        self.stop_button = tk.Button(self, text="Stop", command=self.on_stop_button_press)
        self.stop_button.pack(side="left", padx=0, pady=0)

        self.pause_button = tk.Button(self, text="Pausa", command=self.on_pause_button_press)
        self.pause_button.pack(side="left", padx=0, pady=0)

        self.force_on_button = tk.Button(self, text="Forza ON", command=self.on_force_poweron_button_press)
        self.force_on_button.pack(side="left", padx=0, pady=0)

        self.force_off_button = tk.Button(self, text="Forza OFF", command=self.on_force_poweronff_button_press)
        self.force_off_button.pack(side="left", padx=0, pady=0)

        self.pause_status_label = tk.Label(self, text="Stato: In esecuzione")
        self.pause_status_label.pack(side="left", padx=0, pady=0)
    
    def on_start_button_press(self):
        pass
    
    def on_stop_button_press(self):
        pass
    
    def on_pause_button_press(self):
        pass
    
    def on_force_poweron_button_press(self):
        pass
    
    def on_force_poweronff_button_press(self):
        pass

class InfoFrame(tk.LabelFrame):
    def __init__(self, parent, row, col, padx, pady, sticky):
        super().__init__(parent, text="Info")
        self.grid(row=row, column=col, padx=padx, pady=pady, sticky=sticky)

        self.elapsed_time_label = tk.Label(self, text="Test non ancora partito.")
        self.elapsed_time_label.pack(side="left", padx=5)

        self.cycle_count_label = tk.Label(self, text="Accensioni eseguite: 0")
        self.cycle_count_label.pack(side="left", padx=5)

        self.anomaly_count_label = tk.Label(self, text="Accensioni con anomalia: 0")
        self.anomaly_count_label.pack(side="left", padx=5)

class IpTableFrame(tk.LabelFrame):
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