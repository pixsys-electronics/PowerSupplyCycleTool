import tkinter as tk

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