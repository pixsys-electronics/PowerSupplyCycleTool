import pyvisa as visa
#import visa
import time
import os
import json
import netifaces as ni
import socket
import netaddr
import datetime
import logging

_delay = 0.1  # in seconds

class dp832:
    def __init__(self):
        self.rm = visa.ResourceManager()
        self.inst = None
    
    def is_initialized(self) -> bool:
        self.inst is None
    
    def connect(self, ip):
        time.sleep(1)
        self.inst = self.rm.open_resource(f"TCPIP::{ip}::INSTR")
        time.sleep(1)
        self.inst.write("SYST:REM")
        time.sleep(1)

    def disconnect(self):
        time.sleep(1)
        self.inst.write("SYST:LOC")
        time.sleep(1)
        self.inst.close()
        time.sleep(1)
    
    def setVoltage(self, channel, voltage):
        #command = ':INST:NSEL %s' % channel
        self.inst.write(f"INST CH{channel}")
        time.sleep(_delay)
        #command = ':VOLT %s' % voltage
        self.inst.write(f"VOLT {voltage}")
        time.sleep(_delay)
    
    def ON(self, channel):
        time.sleep(_delay)
        self.inst.write(f"OUTP CH{channel},ON")
        time.sleep(_delay)

    def OFF(self, channel):
        time.sleep(_delay)
        self.inst.write(f"OUTP CH{channel},OFF")
        time.sleep(_delay)


    def select_output(self, chan):
        # define a CHANNEL SELECT function
        command = ':INST:NSEL %s' % chan
        self.inst.write(command)
        time.sleep(_delay)

    def toggle_output(self, chan, state):
        # define a TOGGLE OUTPUT function
        command = ':OUTP CH%s,%s' % (chan, state)
        self.inst.write(command)
        time.sleep(_delay)

    def set_voltage(self, chan, val):
        # define a SET VOLTAGE function
        command = ':INST:NSEL %s' % chan
        self.inst.write(command)
        time.sleep(_delay)
        command = ':VOLT %s' % val
        self.inst.write(command)
        time.sleep(_delay)