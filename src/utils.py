import datetime
import subprocess
import concurrent.futures
from urllib3.exceptions import InsecureRequestWarning
import csv
import os
from ipaddress import IPv4Address
from ordered_set import OrderedSet
import io
import git
from paramiko import AutoAddPolicy, SSHClient
from concurrent.futures import Future, ThreadPoolExecutor
import re
from pyModbusTCP.client import ModbusClient

class ModbusRegisterAddress:
    PowerOnCounter = 0
    TimeCounter = 1

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
    _, stdout, stderr = ssh.exec_command(command)
    _ = stdout.read()
    _ = stderr.read()
    ssh.close()

def run_modbus_read_registers(host: IPv4Address, reg_addr: int, reg_num: int, timeout: float):
    c = ModbusClient(host=str(host), auto_open=True, auto_close=True, timeout=timeout)
    regs = c.read_holding_registers(reg_addr, reg_num)
    return regs

def run_modbus_write_regiter(host: IPv4Address, reg_addr: int, value: int, timeout: float):
    c = ModbusClient(host=str(host), auto_open=True, auto_close=True, timeout=timeout)
    ok = c.write_single_register(reg_addr, value)
    return ok

# check if a given url returns HTTP code 200 (success) using curl
# throws subprocess.TimeoutExpired or a generic exception
def curl(url: str, timeout: float) -> (datetime.datetime | None):
    result = subprocess.run(
        ['curl', '-k', '-s', '-o', '/dev/null', '-w', '%{http_code}', url],
        timeout=timeout,
        capture_output=True,
        text=True
    )
    timestamp = None
    if result.stdout.strip() == '200':
        timestamp = datetime.datetime.now()
    
    return timestamp

# returns an dict where the key is an URL (string) and the value is its completed future
# this way we can handle the future result outside of this function
def broadcast_ping(url_list: set[str], timeout: float) -> dict[str, Future[datetime.datetime | None]]:
    # spawn a bunch of workers to start the pinging process
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        # run a different thread for each URL to ping and
        # create a dictionary where the future is the key and the URL is the value
        future_to_ip = {executor.submit(curl, url, timeout): url for url in url_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

# returns a dict where the key is the IP and the value is its completed future
def broadcast_ssh_command(ip_list: set[IPv4Address], username: str, password: str, command: str) -> dict[IPv4Address, Future[None]]:
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

def broadcast_modbus_read_register(ip_list: set[IPv4Address], reg_addr: int, reg_num: int, timeout: float) -> dict[IPv4Address, Future[list | None]]:
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(run_modbus_read_registers, ip, reg_addr, reg_num, timeout): ip for ip in ip_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

def broadcast_modbus_write_register(ip_list: set[IPv4Address], reg_addr: int, reg_value: int, timeout: float) -> dict[IPv4Address, Future[bool]]:
    future_results = dict()
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_ip = {executor.submit(run_modbus_write_regiter, ip, reg_addr, reg_value, timeout): ip for ip in ip_list}
        
        # wait until every thread has finished, then iterate over each response and check it
        for f in concurrent.futures.as_completed(future_to_ip.keys()):
            ip = future_to_ip[f]
            future_results[ip] = f
    
    return future_results

def broadcast_modbus_read_poweron_counter(ip_list: list[IPv4Address], timeout: float) -> dict[IPv4Address, Future[list | None]]:
    return broadcast_modbus_read_register(ip_list, ModbusRegisterAddress.PowerOnCounter, 1, timeout)

def broadcast_modbus_write_poweron_counter(ip_list: list[IPv4Address], reg_value: int, timeout: float) -> dict[IPv4Address, Future[bool]]:
    return broadcast_modbus_write_register(ip_list, ModbusRegisterAddress.PowerOnCounter, reg_value, timeout)

def broadcast_modbus_write_time_counter(ip_list: list[IPv4Address], reg_value: int, timeout: float) -> dict[IPv4Address, Future[bool]]:
    return broadcast_modbus_write_register(ip_list, ModbusRegisterAddress.TimeCounter, reg_value, timeout)
