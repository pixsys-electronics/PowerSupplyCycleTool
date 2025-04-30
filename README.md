# TestbenchManager

## Description
**TestbenchManager** is a graphical tool designed to test a set of devices connected to the network using different tecniques. It is able to:

- communicate with a remote power supply unit over TCP/IP (dp832)
- send HTTP requests using [curl](https://curl.se/)
- run SSH commands to remote devices
- exchange data using [MODBUS](https://en.wikipedia.org/wiki/Modbus) protocol

**TestbenchManager** handles the testing procedure, the GUI and the logging using python "multithreading".

## State machine
The workflow for the testing procedure is handled using a state machine
![State machine image](assets/state_machine.png)

## Configuration
**TestbenchManager** provides a persistent configuration file in a JSON format, which can be edited using the GUI.

### PSU
The user can choose to:
- enable the remote PSU connection
- insert the IP address of the remote PSU

### Timing
- Ping delay: the time between the start of the cycle and the ping procedure
- Intra-URL ping check: the time between two consecutive ping-checks (timeout excluded)
- Power-off post delay: the time between the end of the power-off procedure and the next test iteration
- Max. Intra-URL ping delay: the maximum time between the first device that answers to a ping and the others
- Starting cycle count: the number of cycles to start with. This parameter is mainly used to check the synchronization between the tool and the devices under test

### SSH
# TODO

### MODBUS
# TODO

## URL
**TestbenchManager** picks the URLs to test from the *urls.csv* file, which is also editable from the GUI.

## Env
- Python 3.11.2

## Setup (Linux - Debian 12)
```sh
apt install python3-tk
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run
```sh
python PowerSupplyCycleTool.py
```
