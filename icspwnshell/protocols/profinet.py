import sys
import time
import threading
import string
import socket
import struct
import uuid
import optparse
from binascii import hexlify, unhexlify
from scapy.all import conf, sniff, srp, Ether

class Profinet:
    def __init__(self, target, port):
        self.target = target
        self.port = port
        self.cfg_dst_mac = '01:0e:cf:00:00:00' # Siemens family
        self.cfg_sniff_time = 2 # seconds
        self.sniffed_packets = None

    def get_src_iface(self):
        return conf.iface

    def get_src_mac(self):
        return ':'.join(['{:02x}'.format((uuid.getnode() >> i) & 0xff) for i in range(0,8*6,8)][::-1])

    def sniff_packets(self, src_iface):
        self.sniffed_packets = sniff(iface=src_iface, filter='ether proto 0x8892', timeout=self.cfg_sniff_time)

    def is_printable(self, data):
        printset = set(string.printable)
        return set(data).issubset(printset)

    def parse_load(self, data, src):
        type_of_station = None
        name_of_station = None
        vendor_id = None
        device_id = None
        device_role = None
        ip_address = None
        subnet_mask = None
        standard_gateway = None
        try:
            data = hexlify(data)
            PROFINET_DCPDataLength = int(data[20:24], 16)
            start_of_Block_Device_Options = 24
            Block_Device_Options_DCPBlockLength = int(data[start_of_Block_Device_Options + 2*2:start_of_Block_Device_Options + 4*2], 16)
            
            start_of_Block_Device_Specific = start_of_Block_Device_Options + Block_Device_Options_DCPBlockLength*2 + 4*2
            Block_Device_Specific_DCPBlockLength = int(data[start_of_Block_Device_Specific+2*2:start_of_Block_Device_Specific+4*2], 16)
            
            padding = Block_Device_Specific_DCPBlockLength%2
            
            start_of_Block_NameOfStation = start_of_Block_Device_Specific + Block_Device_Specific_DCPBlockLength*2 + (4+padding)*2
            Block_NameOfStation_DCPBlockLength = int(data[start_of_Block_NameOfStation+2*2:start_of_Block_NameOfStation+4*2], 16)
            
            padding = Block_NameOfStation_DCPBlockLength%2

            start_of_Block_Device_ID = start_of_Block_NameOfStation + Block_NameOfStation_DCPBlockLength*2 + (4+padding)*2
            Block_DeviceID_DCPBlockLength = int(data[start_of_Block_Device_ID+2*2:start_of_Block_Device_ID+4*2], 16)
            __tmp = data[start_of_Block_Device_ID+4*2:start_of_Block_Device_ID+4*2+Block_DeviceID_DCPBlockLength*2][4:]
            vendor_id, device_id = __tmp[:4], __tmp[4:]
            
            padding = Block_DeviceID_DCPBlockLength%2

            start_of_Block_DeviceRole = start_of_Block_Device_ID + Block_DeviceID_DCPBlockLength*2 + (4+padding)*2
            Block_DeviceRole_DCPBlockLength = int(data[start_of_Block_DeviceRole+2*2:start_of_Block_DeviceRole+4*2], 16)
            device_role = data[start_of_Block_DeviceRole+4*2:start_of_Block_DeviceRole+4*2+Block_DeviceRole_DCPBlockLength*2][4:6]
            
            padding = Block_DeviceRole_DCPBlockLength%2

            start_of_Block_IPset = start_of_Block_DeviceRole + Block_DeviceRole_DCPBlockLength*2 + (4+padding)*2
            Block_IPset_DCPBlockLength = int(data[start_of_Block_IPset+2*2:start_of_Block_IPset+4*2], 16)
            __tmp = data[start_of_Block_IPset+4*2:start_of_Block_IPset+4*2+Block_IPset_DCPBlockLength*2][4:]
            ip_address_hex, subnet_mask_hex, standard_gateway_hex = __tmp[:8], __tmp[8:16], __tmp[16:]
            ip_address = socket.inet_ntoa(struct.pack(">L", int(ip_address_hex, 16)))
            subnet_mask = socket.inet_ntoa(struct.pack(">L", int(subnet_mask_hex, 16)))
            standard_gateway = socket.inet_ntoa(struct.pack(">L", int(standard_gateway_hex, 16)))
            
            tos = data[start_of_Block_Device_Specific+4*2 : start_of_Block_Device_Specific+4*2+Block_Device_Specific_DCPBlockLength*2][4:]
            nos = data[start_of_Block_NameOfStation+4*2 : start_of_Block_NameOfStation+4*2+Block_NameOfStation_DCPBlockLength*2][4:]
            type_of_station = unhexlify(tos)
            name_of_station = unhexlify(nos)
            if not self.is_printable(type_of_station):
                type_of_station = 'not printable'
            if not self.is_printable(name_of_station):
                name_of_station = 'not printable'
        except:
            print(f"%s: %s" % (src, str(sys.exc_info())))
        return type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway


    def create_packet_payload():
        pass