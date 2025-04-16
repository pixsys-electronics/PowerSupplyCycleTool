from ipaddress import IPv4Address, ip_address
import json


class TestBenchConnectionConfig:
    psu_address: IPv4Address
    psu_enabled: bool

    def __init__(self, psu_address: IPv4Address, psu_enabled: bool):
        self.psu_address = psu_address
        self.psu_enabled = psu_enabled
    
    def as_dict(self)->dict:
        return {
            "psu_address": str(self.psu_address),
            "psu_enabled": str(self.psu_enabled)
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
            "username": self.username,
            "password": self.password,
            "command": self.command,
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

class TestBenchModbusConfig:
    automatic_cycle_count_check_enabled: bool
    register_address: int
    register_value: int
    
    def __init__(self, automatic_cycle_count_check_enabled: bool, register_address: int, register_value: int):
        self.automatic_cycle_count_check_enabled = automatic_cycle_count_check_enabled
        self.register_address = register_address
        self.register_value = register_value
    
    def as_dict(self)->dict:
        return {
            "automatic_cycle_count_check_enabled": str(self.automatic_cycle_count_check_enabled),
            "register_address": self.register_address,
            "register_value": self.register_value,
        }

class TestBenchConfig:
    connection: TestBenchConnectionConfig
    timing: TestBenchTimingConfig
    ssh: TestBenchSSHConfig
    modbus: TestBenchModbusConfig

    def __init__(self, connection: TestBenchConnectionConfig, timing: TestBenchTimingConfig, ssh: TestBenchSSHConfig, modbus: TestBenchModbusConfig):
        self.connection = connection
        self.timing = timing
        self.ssh = ssh
        self.modbus = modbus
    
    @staticmethod
    def from_json(file_path: str):
        data = config_from_json(file_path)
        
        connection = data["connection"]
        psu_address = ip_address(connection["psu_address"])
        psu_enabled = connection["psu_enabled"] == "True"
        connection = TestBenchConnectionConfig(psu_address, psu_enabled)

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
        
        modbus = data["modbus"]
        automatic_cycle_count_check_enabled = modbus["automatic_cycle_count_check_enabled"] == "True"
        register_address = int(modbus["register_address"])
        register_value = int(modbus["register_value"])
        
        modbus = TestBenchModbusConfig(automatic_cycle_count_check_enabled, register_address, register_value)

        return TestBenchConfig(connection, timing, ssh, modbus)

    def as_dict(self) -> dict:
        return {
            "connection": self.connection.as_dict(),
            "timing": self.timing.as_dict(),
            "ssh": self.ssh.as_dict(),
            "modbus": self.modbus.as_dict(),
        }

def config_from_json(file_path: str):
    data = {}
    with open(file_path, 'r') as file:
        data = json.load(file)
    return data
