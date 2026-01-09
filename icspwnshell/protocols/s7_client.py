#! /usr/bin/env python
# coding:utf-8
# Author: WenZhe Zhu
from icspwnshell.interfaces.protocol import Base
from icspwnshell.protocols.cotp import *
from icspwnshell.protocols.s7comm import *
from scapy.supersocket import StreamSocket
import socket
import os, sys, re, time, string, struct, socket
from subprocess import Popen, PIPE
import psutil
from multiprocessing.pool import ThreadPool
from binascii import hexlify, unhexlify
from ctypes import CDLL, POINTER, Structure, c_void_p, c_char_p, c_ushort, c_char, c_long, c_int, c_uint, c_ubyte, byref, create_string_buffer
from ctypes.util import find_library
try:
    import s7, modbus
    s7present = True
except:
    s7present = False
    pass

from scapy.all import *

VAR_NAME_TYPES = {
    'P': 0x80,      # I/O
    'I': 0x81,      # Memory area of inputs
    'Q': 0x82,      # Memory area of outputs
    'M': 0x83,      # Memory area of bit memory
    'DB': 0x84,     # Data block
    'L': 0x86,      # Local data
    'V': 0x87       # Previous local data
}
##### Classes
class sockaddr(Structure):
    _fields_ = [("sa_family", c_ushort),
                ("sa_data", c_char * 14)]
class pcap_addr(Structure):
    pass
pcap_addr._fields_ = [('next', POINTER(pcap_addr)),
                      ('addr', POINTER(sockaddr)),
                      ('netmask', POINTER(sockaddr)),
                      ('broadaddr', POINTER(sockaddr)),
                      ('dstaddr', POINTER(sockaddr))]

class pcap_if(Structure):
    pass
pcap_if._fields_ = [('next', POINTER(pcap_if)),
                    ('name', c_char_p),
                    ('description', c_char_p),
                    ('addresses', POINTER(pcap_addr)),
                    ('flags', c_int)]
class timeval(Structure):
    pass
timeval._fields_ = [('tv_sec', c_long),
                    ('tv_usec', c_long)]
class pcap_pkthdr(Structure):
    _fields_ = [('ts', timeval),
                ('caplen', c_int),
                ('len', c_int)]

##### Initialize Pcap
if os.name == 'nt':
    try:
        _lib = CDLL('wpcap.dll')
    except:
        print('Error: WinPcap not found!')
        print('Please download here: https://www.winpcap.org/install')
        #raw_input('Press [Enter] to close')
        sys.exit(1)
else:
    pcaplibrary = find_library('pcap')
    if pcaplibrary == None or str(pcaplibrary) == '':
        print('Error: Pcap library not found!')
        print('Please install with: e.g. apt-get install libpcap0.8')
        #raw_input('Press [Enter] to close')
        sys.exit(1)
    _lib = CDLL(pcaplibrary)

## match DLL function to list all devices
pcap_findalldevs = _lib.pcap_findalldevs
pcap_findalldevs.restype = c_int
pcap_findalldevs.argtypes = [POINTER(POINTER(pcap_if)), c_char_p]
## match DLL function to open a device
pcap_open_live = _lib.pcap_open_live
pcap_open_live.restype = POINTER(c_void_p)
pcap_open_live.argtypes = [c_char_p, c_int, c_int, c_int, c_char_p]
## match DLL function to send a raw packet
pcap_sendpacket = _lib.pcap_sendpacket
pcap_sendpacket.restype = c_int
pcap_sendpacket.argtypes = [POINTER(c_void_p), POINTER(c_ubyte), c_int]
## match DLL function to close a device
pcap_close = _lib.pcap_close
pcap_close.restype = None
pcap_close.argtypes = [POINTER(c_void_p)]
## match DLL function to get error message
pcap_geterr = _lib.pcap_geterr
pcap_geterr.restype = c_char_p
pcap_geterr.argtypes = [POINTER(c_void_p)]
## match DLL function to get next packet
pcap_next_ex = _lib.pcap_next_ex
pcap_next_ex.restype = c_int
pcap_next_ex.argtypes = [POINTER(c_void_p), POINTER(POINTER(pcap_pkthdr)), POINTER(POINTER(c_ubyte))]



class S7Client(Base):
    def __init__(self, name, ip, port=102, src_tsap='\x01\x00', rack=0, slot=2, timeout=2):
        '''

        :param name: Name of this targets
        :param ip: S7 PLC ip
        :param port: S7 PLC port (default: 102)
        :param src_tsap: src_tsap
        :param rack: cpu rack (default: 0)
        :param slot: cpu slot (default: 2)
        :param timeout: timeout of socket (default: 2)
        '''
        super(S7Client, self).__init__(name=name)
        self._ip = ip
        self._port = port
        self._slot = slot
        self._src_tsap = src_tsap
        self._dst_tsap = '\x01' + struct.pack('B', rack * 0x20 + slot)
        self._pdur = 1
        self.protect_level = None
        self._connection = None
        self._connected = False
        self._timeout = timeout
        self._pdu_length = 480
        self.readable = False
        self.writeable = False
        self.authorized = False
        self._password = None
        self._mmc_password = None
        self.is_running = False

    def connect(self):
        sock = socket.socket()
        sock.settimeout(self._timeout)
        sock.connect((self._ip, self._port))
        self._connection = StreamSocket(sock, Raw)
        packet1 = TPKT() / COTPCR()
        packet1.Parameters = [COTPOption() for i in range(3)]
        packet1.PDUType = "CR"
        packet1.Parameters[0].ParameterCode = "tpdu-size"
        packet1.Parameters[0].Parameter = "\x0a"
        packet1.Parameters[1].ParameterCode = "src-tsap"
        packet1.Parameters[2].ParameterCode = "dst-tsap"
        packet1.Parameters[1].Parameter = self._src_tsap
        packet1.Parameters[2].Parameter = self._dst_tsap
        self.send_receive_packet(packet1)
        packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7SetConParameter())
        rsp2 = self.send_receive_s7_packet(packet2)
        if rsp2:
            self._connected = True
        # Todo: Need get pdu length from rsp2

    def _get_cpu_protect_level(self):
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x0232, SZLIndex=0x0004))
        rsp = self.send_receive_s7_packet(packet1)
        self.protect_level = int(str(rsp)[48].encode('hex'))
        self.logger.info("CPU protect level is %s" % self.protect_level)

    def get_target_info(self):
        order_code = ''
        version = ''
        module_type_name = ''
        as_name = ''
        module_name = ''
        serial_number = ''
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x0011, SZLIndex=0x0000))
        rsp1 = self.send_receive_s7_packet(packet1)
        try:
            order_code_data = rsp1[S7ReadSZLDataTreeRsp].Data[:rsp1[S7ReadSZLDataRsp].SZLLength]
            order_code = order_code_data[2:-7]
            version_data = rsp1[S7ReadSZLDataTreeRsp].Data[-3:]
            version = 'V {:x}.{:x}.{:x}'.format(
                int(version_data[0].encode('hex'), 16),
                int(version_data[1].encode('hex'), 16),
                int(version_data[2].encode('hex'), 16),
            )

        except Exception as err:
            self.logger.error("Can't get order code and version from target")
            return order_code, version, module_type_name, as_name, module_name, serial_number

        packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x001c, SZLIndex=0x0000))
        rsp2 = self.send_receive_s7_packet(packet2)
        try:
            module_name_data = rsp2[S7ReadSZLDataTreeRsp].Data[
                rsp2[S7ReadSZLDataRsp].SZLLength + 2:rsp2[S7ReadSZLDataRsp].SZLLength * 2]
            module_name = str(module_name_data[:module_name_data.index('\x00')])
            self.logger.debug("module_name:%s " % module_name)
            as_name_data = rsp2[S7ReadSZLDataTreeRsp].Data[2:rsp2[S7ReadSZLDataRsp].SZLLength]
            as_name = str(as_name_data[:as_name_data.index('\x00')])
            self.logger.debug("as_name:%s " % as_name)
            serial_number_data = rsp2[S7ReadSZLDataTreeRsp].Data[
                               rsp2[S7ReadSZLDataRsp].SZLLength * 4 + 2:rsp2[S7ReadSZLDataRsp].SZLLength * 5]
            serial_number = str(serial_number_data[:serial_number_data.index('\x00')])
            self.logger.debug("serial_number:%s " % serial_number)
            module_type_name_data = rsp2[S7ReadSZLDataTreeRsp].Data[
                               rsp2[S7ReadSZLDataRsp].SZLLength * 5 + 2:rsp2[S7ReadSZLDataRsp].SZLLength * 6]
            module_type_name = str(module_type_name_data[:module_type_name_data.index('\x00')])
            self.logger.debug("module_type_name:%s " % module_type_name)

        except Exception as err:
            self.logger.error("Can't get module info from target")
            return order_code, version, module_type_name, as_name, module_name, serial_number

        return order_code, version, module_type_name, as_name, module_name, serial_number

    def check_privilege(self):
        self._get_cpu_protect_level()
        if self.protect_level == 1:
            self.logger.info("You have full privilege with this targets")
            self.readable = True
            self.writeable = True
        if self.protect_level == 2:
            if self.authorized is True:
                self.logger.info("You have full privilege with this targets")
                self.readable = True
                self.writeable = True
            else:
                self.logger.info("You only have read privilege with this targets")
                self.readable = True
                self.writeable = False
        if self.protect_level == 3:
            if self.authorized is True:
                self.logger.info("You have full privilege with this targets")
                self.readable = True
                self.writeable = True
            else:
                self.logger.info("You can't read or write with this targets")
                self.readable = False
                self.writeable = False

    def auth(self, password):
        """
        
        :param password: Paintext PLC password.
        """
        self.logger.info("Start authenticate with password %s" % password)
        password_hash = self._hash_password(password)
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7PasswordParameterReq(),
                                                    Data=S7PasswordDataReq(Data=password_hash))
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.haslayer(S7PasswordParameterRsp):
            if rsp1[S7PasswordParameterRsp].ErrorCode == 0:
                self.authorized = True
                self.logger.info("Authentication succeed")
            else:
                if self.authorized is True:
                    self.logger.info("Already authorized")
                else:
                    error_code = rsp1[S7PasswordParameterRsp].ErrorCode
                    if error_code in S7_ERROR_CLASS.keys():
                        self.logger.error("Got error code: %s" % S7_ERROR_CLASS[error_code])
                    else:
                        self.logger.error("Get error code: %s" % hex(error_code))
                    self.logger.error("Authentication failure")
            self.check_privilege()
        else:
            self.logger.info("Receive unknown format packet, authentication failure")

    def clean_session(self):
        self.logger.info("Start clean the session")
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7CleanSessionParameterReq(),
                                                    Data=S7CleanSessionDataReq())
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.haslayer(S7CleanSessionParameterRsp):
            if rsp1[S7CleanSessionParameterRsp].ErrorCode == 0:
                self.authorized = False
                self.logger.info("session cleaned")
            else:
                error_code = rsp1[S7CleanSessionParameterRsp].ErrorCode
                if error_code in S7_ERROR_CLASS.keys():
                    self.logger.error("Got error code: %s" % S7_ERROR_CLASS[error_code])
                else:
                    self.logger.error("Get error code: %s" % hex(error_code))
        else:
            self.logger.info("Receive unknown format packet, authentication failure")

    def _hash_password(self, password):
        password_hash_new = ''
        if len(password) < 1 or len(password) > 8:
            self.logger.error("Password length must between 1 to 8")
            return None
        else:
            password += '20'.decode('hex') * (8 - len(password))
            for i in range(8):
                if i < 2:
                    temp_data = ord(password[i])
                    temp_data ^= 0x55
                    password_hash_new += str(chr(temp_data))
                else:
                    temp_data1 = ord(password[i])
                    temp_data2 = ord(password_hash_new[i - 2])
                    temp_data1 = temp_data1 ^ 0x55 ^ temp_data2
                    password_hash_new += str(chr(temp_data1))
            return password_hash_new

    def _fix_pdur(self, payload):
        if self._pdur > 65535:
            self._pdur = 1
        try:
            payload.PDUR = self._pdur
            self._pdur += 1
            return payload
        except Exception as err:
            self.logger.error(err)
            return payload

    def send_packet(self, packet):
        if self._connection:
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_packet(self, packet):
        if self._connection:
            try:
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before receive packet!")

    def send_s7_packet(self, packet):
        if self._connection:
            packet = self._fix_pdur(packet)
            try:
                self._connection.send(packet)

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def send_receive_s7_packet(self, packet):
        if self._connection:
            packet = self._fix_pdur(packet)
            try:
                rsp = self._connection.sr1(packet, timeout=self._timeout)
                if rsp:
                    rsp = TPKT(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None

        else:
            self.logger.error("Please create connect before send packet!")

    def receive_s7_packet(self):
        if self._connection:
            try:
                rsp = self._connection.recv()
                if rsp:
                    rsp = TPKT(str(rsp))
                return rsp

            except Exception as err:
                self.logger.error(err)
                return None
        else:
            self.logger.error("Please create connect before receive packet!")

    def upload_block_from_target(self, block_type, block_num, dist='A'):
        """

        :param block_type: "08": 'OB', "09": 'CMOD', "0A": 'DB', "0B": 'SDB', "0C": 'FC',
                            "0D": 'SFC', "0E": 'FB', "0F": 'SFB'
        :param block_num: Block number.
        :param dist: 'A': "Active embedded module", 'B': "Active as well as passive module",
                     'P': "Passive (copied, but not chained) module"
        :return: Block Data
        """
        if self.readable is False:
            self.logger.info("Didn't have read privilege on targets")
            return None
        block_data = ''
        if block_type in S7_BLOCK_TYPE_IN_FILE_NAME.keys():
            file_block_type = block_type
        else:
            for key, name in S7_BLOCK_TYPE_IN_FILE_NAME.iteritems():
                if name == block_type:
                    file_block_type = key
                    break
            else:
                self.logger.error("block_type: %s is incorrect please check again" % block_type)
                return

        if type(block_num) != int:
            self.logger.error("block_num must be int format.")
            return

        file_block_num = "{0:05d}".format(block_num)
        file_name = '_' + file_block_type + file_block_num + dist
        self.logger.info("Start upload %s%s from target" % (block_type, block_num))
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7RequestUploadBlockParameterReq(Filename=file_name))
        rsp1 = self.send_receive_s7_packet(packet1)
        # Todo: Might got some error
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't upload %s%s from target" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None
        packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7UploadBlockParameterReq())
        packet2[S7UploadBlockParameterReq].UploadId = rsp1[S7RequestUploadBlockParameterRsp].UploadId
        while True:
            rsp2 = self.send_receive_s7_packet(packet2)
            if rsp2.ErrorClass != 0x0:
                self.logger.error("Can't upload %s%s from targets" % (block_type, block_num))
                self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
                return None
            self.logger.debug("rsp2: %s" % str(rsp2).encode('hex'))
            block_data += rsp2.Data.Data
            if rsp2.Parameters.FunctionStatus != 1:
                break
        packet3 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7UploadBlockEndParameterReq())
        self.send_receive_s7_packet(packet3)
        self.logger.info("Upload %s%s from target succeed" % (block_type, block_num))
        return block_data

    def get_info_from_block(self, block_data):
        """

        :param block_data: Block data.
        :return: mem_length, mc7_length, block_type, block_num
        """
        try:
            mem_length = struct.unpack('!i', block_data[8:12])[0]
            mc7_length = struct.unpack('!h', block_data[34:36])[0]
            block_type = S7_BLOCK_TYPE_IN_BLOCK[ord(block_data[5])]
            block_num = struct.unpack('!h', block_data[6:8])[0]
            return mem_length, mc7_length, block_type, block_num

        except Exception as err:
            self.logger.error(err)
            return None

    def download_block_to_target(self, block_data, dist='P', transfer_size=462, stop_target=False):
        """ Download block to target and active block.

        :param block_data: Block data to download.
        :param dist: 'A': "Active embedded module", 'B': "Active as well as passive module",
                     'P': "Passive (copied, but not chained) module".
        :param transfer_size: Transfer size for each packet.
        :param stop_target: Stop target PLC before download block, True or False.
        """
        if self.writeable is False:
            self.logger.info("Didn't have write privilege on targets")
            return None
        mem_length, mc7_length, block_type, block_num = self.get_info_from_block(block_data)
        self.logger.info("Start download %s%s to targets" % (block_type, block_num))
        file_block_type = None
        for key, name in S7_BLOCK_TYPE_IN_FILE_NAME.iteritems():
            if name == block_type:
                file_block_type = key
                break
        if not file_block_type:
            self.logger.error("block_type: %s is incorrect please check again" % block_type)
            return

        file_block_num = "{0:05d}".format(block_num)
        file_name = '_' + file_block_type + file_block_num + dist

        load_memory_length = '0' * (6 - len(str(mem_length))) + str(mem_length)
        mc7_length = '0' * (6 - len(str(mc7_length))) + str(mc7_length)
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7RequestDownloadParameterReq(
                                                        Filename=file_name,
                                                        LoadMemLength=load_memory_length,
                                                        MC7Length=mc7_length)
                                                    )
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Download %s%s to targets" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None

        if len(rsp1) > 20:
            download_req = TPKT(rsp1.load)
        else:
            download_req = self.receive_s7_packet()
        # Get pdur from download_req
        self._pdur = download_req.PDUR
        # DownloadBlock
        for i in range(0, len(block_data), transfer_size):
            if i + transfer_size <= len(block_data):
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=1),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                rsp2 = self.send_receive_s7_packet(packet2)
                self._pdur = rsp2.PDUR
            else:
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=0),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                self.send_s7_packet(packet2)
        # DownloadBlockEnd
        download_end_req = self.receive_s7_packet()
        self._pdur = download_end_req.PDUR
        packet3 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData", Parameters=S7DownloadEndParameterRsp())
        self.send_s7_packet(packet3)
        # Insert block
        self.logger.debug("File_name:%s" % ('\x00' + file_name[1:]))
        packet4 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7PIServiceParameterReq(
                                                        ParameterBlock=S7PIServiceParameterBlock(
                                                            FileNames=['\x00' + file_name[1:]]),
                                                        PI="_INSE")
                                                    )
        # Todo: Might have a better way to do this
        # packet4[S7PIServiceParameterReq].ParameterBlock = S7PIServiceParameterBlock(FileNames=[file_name[1:]])
        rsp4 = self.send_receive_s7_packet(packet4)
        if rsp4.ErrorClass != 0x0:
            self.logger.error("Can't insert %s%s to targets" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None
        self.logger.info("Download %s%s to target succeed" % (block_type, block_num))

    def download_block_to_target_only(self, block_data, dist='P', transfer_size=462, stop_target=False):
        """ Download block to target only (didn't active block).

        :param block_data: Block data to download.
        :param dist: 'A': "Active embedded module", 'B': "Active as well as passive module",
                     'P': "Passive (copied, but not chained) module".
        :param transfer_size: Transfer size for each packet.
        :param stop_target: Stop target PLC before download block, True or False.
        """
        if self.writeable is False:
            self.logger.info("Didn't have write privilege on targets")
            return None
        mem_length, mc7_length, block_type, block_num = self.get_info_from_block(block_data)
        self.logger.info("Start download %s%s to targets" % (block_type, block_num))
        file_block_type = None
        for key, name in S7_BLOCK_TYPE_IN_FILE_NAME.iteritems():
            if name == block_type:
                file_block_type = key
                break
        if not file_block_type:
            self.logger.error("block_type: %s is incorrect please check again" % block_type)
            return

        file_block_num = "{0:05d}".format(block_num)
        file_name = '_' + file_block_type + file_block_num + dist

        load_memory_length = '0' * (6 - len(str(mem_length))) + str(mem_length)
        mc7_length = '0' * (6 - len(str(mc7_length))) + str(mc7_length)
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                    Parameters=S7RequestDownloadParameterReq(
                                                        Filename=file_name,
                                                        LoadMemLength=load_memory_length,
                                                        MC7Length=mc7_length)
                                                    )
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Download %s%s to targets" % (block_type, block_num))
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return None

        if len(rsp1) > 20:
            download_req = TPKT(rsp1.load)
        else:
            download_req = self.receive_s7_packet()
        # Get pdur from download_req
        self._pdur = download_req.PDUR
        # DownloadBlock
        for i in range(0, len(block_data), transfer_size):
            if i + transfer_size <= len(block_data):
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=1),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                rsp2 = self.send_receive_s7_packet(packet2)
                self._pdur = rsp2.PDUR
            else:
                packet2 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData",
                                                            Parameters=S7DownloadParameterRsp(FunctionStatus=0),
                                                            Data=S7DownloadDataRsp(
                                                                Data=block_data[i:i + transfer_size]))
                self.send_s7_packet(packet2)
        # DownloadBlockEnd
        download_end_req = self.receive_s7_packet()
        self._pdur = download_end_req.PDUR
        packet3 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="AckData", Parameters=S7DownloadEndParameterRsp())
        self.send_s7_packet(packet3)
        self.logger.info("Download %s%s to target succeed" % (block_type, block_num))

    def get_target_status(self):
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="UserData", Parameters=S7ReadSZLParameterReq(),
                                                    Data=S7ReadSZLDataReq(SZLId=0x0424, SZLIndex=0x0000))
        rsp = self.send_receive_s7_packet(packet1)
        status = str(rsp)[44]
        if status == '\x08':
            self.logger.info("Target is in run mode")
            self.is_running = True
        elif status == '\x04':
            self.logger.info("Target is in stop mode")
            self.is_running = False
        else:
            self.logger.info("Target is in unknown mode")
            self.is_running = False

    def stop_target(self):
        self.get_target_status()
        if not self.is_running:
            self.logger.info("Target is already stop")
            return
        self.logger.info("Trying to stop targets")
        packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7StopCpuParameterReq())
        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Stop Target")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return
        time.sleep(2)  # wait targets to stop
        self.get_target_status()

    def start_target(self, cold=False):
        ''' Start target PLC

        :param cold: Doing cold restart, True or False.
        '''
        self.get_target_status()
        if self.is_running:
            self.logger.info("Target is already running")
            return
        self.logger.info("Trying to start targets")

        if cold:
            packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7PIServiceParameterReq(
                ParameterBlock=S7PIServiceParameterStringBlock()))
        else:
            packet1 = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7PIServiceParameterReq())

        rsp1 = self.send_receive_s7_packet(packet1)
        if rsp1.ErrorClass != 0x0:
            self.logger.error("Can't Start Target")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp1.ErrorClass, rsp1.ErrorCode))
            return
        time.sleep(2)  # wait targets to start
        self.get_target_status()

    @staticmethod
    def get_transport_size_from_data_type(data_type):
        for key, name in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.iteritems():
            if isinstance(data_type, str):
                if name.startswith(data_type.upper()):
                    return key
            elif isinstance(data_type, int):
                return data_type
        return None

    def get_item_pram_from_item(self, item):
        block_num = ''
        area_type = ''
        address = ''
        transport_size = ''
        try:
            for key in VAR_NAME_TYPES:
                if isinstance(item[0], str):
                    if item[0].startswith(key):
                        area_type = VAR_NAME_TYPES[key]

                elif isinstance(item[0], int):
                    if item[0] in VAR_NAME_TYPES.keys():
                        area_type = item[0]

            # Data block
            if area_type == 0x84:
                block_num = int(item[0][2:])
            else:
                block_num = 0

            if isinstance(item[1], str):
                address_data = item[1].split('.')
                address = int(address_data[0]) * 8 + int(address_data[1])

            elif isinstance(item[1], int):
                address = item[1]

            else:
                self.logger.error("Address: %s is not string or int format, please check again" % item[1])

            transport_size = self.get_transport_size_from_data_type(item[2])

        except Exception as err:
            self.logger.error("Can't get item parameter with var_name: %s with error: \r %s" % (item, err))
            return transport_size, block_num, area_type, address

        return transport_size, block_num, area_type, address

    @staticmethod
    def bytes_to_bit_array(bytes_data):
        bit_array = ""
        for data in bytes_data:
            bit_array += '{:08b}'.format(ord(data))
        return map(int, list(bit_array))

    def _unpack_data_with_transport_size(self, req_item, rsp_item):
        # ref http://www.plcdev.com/step_7_elementary_data_types
        if isinstance(rsp_item, S7ReadVarDataItemsRsp):
            try:
                req_type = req_item.TransportSize
                if req_type not in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.keys():
                    return []
                # BIT (0x01)
                elif req_type == 0x01:
                    bit_list = self.bytes_to_bit_array(rsp_item.Data)
                    return bit_list[-1:][0]
                # BYTE (0x02)
                elif req_type == 0x02:
                    byte_list = list(rsp_item.Data)
                    return map(ord, byte_list)
                # CHAR (0x03)
                elif req_type == 0x03:
                    char_list = list(rsp_item.Data)
                    return char_list
                # WORD (0x04) 2 bytes Decimal number unsigned
                elif req_type == 0x04:
                    word_data = rsp_item.Data
                    word_list = [struct.unpack('!H', word_data[i:i+2])[0] for i in range(0, len(word_data), 2)]
                    return word_list
                # INT (0x05) 2 bytes Decimal number signed
                elif req_type == 0x05:
                    int_data = rsp_item.Data
                    int_list = [struct.unpack('!h', int_data[i:i+2])[0] for i in range(0, len(int_data), 2)]
                    return int_list
                # DWORD (0x06) 4 bytes Decimal number unsigned
                elif req_type == 0x06:
                    dword_data = rsp_item.Data
                    dword_list = [struct.unpack('!I', dword_data[i:i+4])[0] for i in range(0, len(dword_data), 4)]
                    return dword_list
                # DINT (0x07) 4 bytes Decimal number signed
                elif req_type == 0x07:
                    dint_data = rsp_item.Data
                    dint_list = [struct.unpack('!i', dint_data[i:i+4])[0] for i in range(0, len(dint_data), 4)]
                    return dint_list
                # REAL (0x08) 4 bytes IEEE Floating-point number
                elif req_type == 0x08:
                    dint_data = rsp_item.Data
                    dint_list = [struct.unpack('!f', dint_data[i:i+4])[0] for i in range(0, len(dint_data), 4)]
                    return dint_list
                else:
                    return rsp_item.Data

            except Exception as err:
                return []
        return []

    @staticmethod
    def _pack_data_with_transport_size(req_item, data_list):
        # ref http://www.plcdev.com/step_7_elementary_data_types
        if isinstance(req_item, S7WriteVarItemsReq):
            try:
                req_type = req_item.TransportSize
                if req_type not in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.keys():
                    return []
                # BIT (0x01)
                elif req_type == 0x01:
                    # Only support write 1 bit.
                    if isinstance(data_list, list):
                        bit_data = chr(data_list[0])
                    else:
                        bit_data = chr(data_list)
                    return bit_data
                # BYTE (0x02)
                elif req_type == 0x02:
                    byte_data = ''.join(chr(x) for x in data_list)
                    return byte_data
                # CHAR (0x03)
                elif req_type == 0x03:
                    char_data = ''.join(x for x in data_list)
                    return char_data
                # WORD (0x04) 2 bytes Decimal number unsigned
                elif req_type == 0x04:
                    word_data = ''.join(struct.pack('!H', x) for x in data_list)
                    return word_data
                # INT (0x05) 2 bytes Decimal number signed
                elif req_type == 0x05:
                    int_data = ''.join(struct.pack('!h', x) for x in data_list)
                    return int_data
                # DWORD (0x06) 4 bytes Decimal number unsigned
                elif req_type == 0x06:
                    dword_data = ''.join(struct.pack('!I', x) for x in data_list)
                    return dword_data
                # DINT (0x07) 4 bytes Decimal number signed
                elif req_type == 0x07:
                    dint_data = ''.join(struct.pack('!i', x) for x in data_list)
                    return dint_data
                # REAL (0x08) 4 bytes IEEE Floating-point number
                elif req_type == 0x08:
                    real_data = ''.join(struct.pack('!f', x) for x in data_list)
                    return real_data
                # Other data
                else:
                    other_data = ''.join(x for x in data_list)
                    return other_data

            except Exception as err:
                return ''
        return ''

    @staticmethod
    def _convert_transport_size_from_parm_to_data(parm_transport_size):
        if parm_transport_size not in S7_TRANSPORT_SIZE_IN_PARM_ITEMS.keys():
            return None
        else:
            # BIT (0x03)
            if parm_transport_size == 0x01:
                return 0x03
            # BYTE/WORD/DWORD (0x04)
            elif parm_transport_size in (0x02, 0x04, 0x06):
                return 0x04
            # INTEGER (0x05)
            elif parm_transport_size in (0x05, 0x07):
                return 0x05
            # REAL (0x07)
            elif parm_transport_size == 0x08:
                return 0x07
            # OCTET STRING (0x09)
            else:
                return 0x09

    def read_var(self, items):
        '''

        :param items:
        :return: Return data list of read_var items.
        '''
        read_items = []
        items_data = []

        if isinstance(items, list):
            for i in range(len(items)):
                try:
                    transport_size, block_num, area_type, address = self.get_item_pram_from_item(items[i])
                    length = int(items[i][3])
                    if transport_size:
                        read_items.append(S7ReadVarItemsReq(TransportSize=transport_size,
                                                            GetLength=length,
                                                            BlockNum=block_num,
                                                            AREAType=area_type,
                                                            Address=address
                                                            )
                                          )
                except Exception as err:
                    self.logger.error("Can't create read var packet because of: \r %s" % err)
                    return None
        else:
            self.logger.error("items is not list please check again")
            return None

        packet = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job", Parameters=S7ReadVarParameterReq(
            Items=read_items))
        rsp = self.send_receive_s7_packet(packet)
        if rsp.ErrorClass != 0x0:
            self.logger.error("Can't Read var from Target")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp.ErrorClass, rsp.ErrorCode))
            return None
        if rsp.haslayer(S7ReadVarDataItemsRsp):
            for i in range(len(rsp[S7ReadVarDataRsp].Items)):
                req_item = read_items[i][S7ReadVarItemsReq]
                rsp_item = rsp[S7ReadVarDataRsp].Items[i]
                if rsp_item.ReturnCode == 0xff:
                    rsp_item_data = self._unpack_data_with_transport_size(req_item, rsp_item)
                    items_data.append(rsp_item_data)
                else:
                    items_data.append('')
        return items_data

    def write_var(self, items):
        """

        :param items:
        :return:
        """
        write_items = []
        items_data = []
        write_data_rsp = []
        if isinstance(items, list):
            for i in range(len(items)):
                try:
                    transport_size, block_num, area_type, address = self.get_item_pram_from_item(items[i])
                    length = len(items[i][3])
                    if transport_size:
                        write_items.append(S7WriteVarItemsReq(TransportSize=transport_size,
                                                              ItemCount=length,
                                                              BlockNum=block_num,
                                                              AREAType=area_type,
                                                              BitAddress=address
                                                              )
                                           )
                        write_data = self._pack_data_with_transport_size(write_items[i], items[i][3])
                        items_data.append(S7WriteVarDataItemsReq(
                            TransportSize=self._convert_transport_size_from_parm_to_data(transport_size),
                            Data=write_data))
                except Exception as err:
                    self.logger.error("Can't create write var packet because of: \r %s" % err)
                    return None
        else:
            self.logger.error("items is not list please check again")
            return None

        packet = TPKT() / COTPDT(EOT=1) / S7Header(ROSCTR="Job",
                                                   Parameters=S7WriteVarParameterReq(Items=write_items),
                                                   Data=S7WriteVarDataReq(Items=items_data))
        rsp = self.send_receive_s7_packet(packet)
        if rsp.ErrorClass != 0x0:
            self.logger.error("Can't write var to Target.")
            self.logger.error("Error Class: %s, Error Code %s" % (rsp.ErrorClass, rsp.ErrorCode))
            return None
        if rsp.haslayer(S7WriteVarDataRsp):
            for rsp_items in rsp[S7WriteVarDataRsp].Items:
                write_data_rsp.append(rsp_items.ReturnCode)
            return write_data_rsp
        else:
            self.logger.error("Unknown response packet format.")
            return None
        
    
    ##### Functions
    def getAllInterfaces():
        def addToArr(array, adapter, ip, mac, device, winguid):
            if len(mac) == 17: # When no or bad MAC address (e.g. PPP adapter), do not add
                array.append([adapter, ip, mac, device, winguid])
            return array

        # Returns twodimensional array of interfaces in this sequence for each interface:
        # [0] = adaptername (e.g. Ethernet or eth0)
        # [1] = Current IP (e.g. 192.168.0.2)
        # [2] = Current MAC (e.g. ff:ee:dd:cc:bb:aa)
        # [3] = Devicename (e.g. Intel 82575LM, Windows only)
        # [4] = DeviceGUID (e.g. {875F7EDB-CA23-435E-8E9E-DFC9E3314C55}, Windows only)
        netcard_info = []
        info = psutil.net_if_addrs()
        for k, v in info.items():
            ninfo = ['', '', '', '', '']
            ninfo[0] = k
            for item in v:
                if item[1] == '127.0.0.1':
                    break
                if item[0] == 2:
                    ninfo[1] = item[1]
                else:
                    ninfo[2] = item[1]

            if ninfo[1] == '':
                continue

            netcard_info.append(ninfo)

        return netcard_info

    ## Listing all NPF adapters and finding the correct one that has the Windows Devicename (\Device\NPF_{GUID})
    def findMatchingNPFDevice(windevicename):
        alldevs = POINTER(pcap_if)()
        errbuf = create_string_buffer(256)
        if pcap_findalldevs(byref(alldevs), errbuf) == -1:
            print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
            sys.exit(1)
        pcapdevices = alldevs.contents
        while pcapdevices:
            if str(pcapdevices.description) == windevicename:
                return pcapdevices.name
            if pcapdevices.next:
                pcapdevices = pcapdevices.next.contents
            else:
                pcapdevices = False
        return ''

    ## Expects hexstring like this 01020304050607 and returns bytearray
    def createPacket(string):
        hexstring = unhexlify(string)
        packet = (c_ubyte * len(hexstring))()
        b = bytearray()
        b.extend(hexstring)
        for i in range(0,len(hexstring)):
            packet[i] = b[i]
        return packet

    ## Actually sends a packet
    def sendRawPacket(npfdevice, ethertype, srcmac, setNetwork=False, networkDataToSet='', dstmac=''):
        if ethertype == '88cc': # LLDP Packet
            dstmac = '0180c200000e'
            data = '0210077365727665722d6e6574776f726b6d040907706f72742d303031060200140a0f5345525645522d4e4554574f524b4d0c60564d776172652c20496e632e20564d77617265205669727475616c20506c6174666f726d2c4e6f6e652c564d776172652d34322033362036642039622034302062642038642038302d66302037362061312066302035332030392039352032370e040080008010140501ac101e660200000001082b0601040181c06efe08000ecf0200000000fe0a000ecf05005056b6feb6fe0900120f0103ec0300000000'
        elif ethertype == '8100': # PN-DCP, Profinet Discovery Packet, ethertype '8100'
            dstmac = '010ecf000000'
            data = '00008892fefe05000400000300800004ffff00000000000000000000000000000000000000000000000000000000'
        elif ethertype == '8892' and setNetwork:
            ## Create packet to set networkdata, expect data in hexstring
            data = ('fefd 04 00 04000001 0000 0012 0102 000e 0001' + networkDataToSet + '0000 0000 0000 0000 0000 0000').replace(' ','') # Working
        elif ethertype == '8892' and not setNetwork:
            ## Create custom packet with 'networkDataToSet' as the data (including length) and dstmac as dstmac
            data = networkDataToSet

        ## Get packet as a bytearray
        packet = createPacket(dstmac + srcmac + ethertype + data)

        ## Send the packet
        fp = c_void_p
        errbuf = create_string_buffer(256)
        fp = pcap_open_live(npfdevice, 65535, 1, 1000, errbuf)
        if not bool(fp):
            print("\nUnable to open the adapter. %s is not supported by Pcap\n" % interfaces[int(answer - 1)][0])
            sys.exit(1)

        if pcap_sendpacket(fp, packet, len(packet)) != 0:
            print ("\nError sending the packet: %s\n" % pcap_geterr(fp))
            sys.exit(1)

        pcap_close(fp)
        return packet

    ## Receive packets, expect device to receive on, src mac address + ethertype to filter on and timeout in seconds
    def receiveRawPackets(npfdevice, timeout, srcmac, ethertype, stopOnReceive=False):
        receivedRawData = []
        fp = c_void_p
        errbuf = create_string_buffer(256)
        fp = pcap_open_live(npfdevice, 65535, 1, 1000, errbuf)
        if not bool(fp):
            print("\nUnable to open the adapter. %s is not supported by Pcap\n" % interfaces[int(answer - 1)][0])
            sys.exit(1)

        header = POINTER(pcap_pkthdr)()
        pkt_data = POINTER(c_ubyte)()
        receivedpacket = pcap_next_ex(fp, byref(header), byref(pkt_data))
        ## Regular handler, loop until told otherwise (or with timer)
        timer = time.time() + int(timeout)
        i = 0
        while receivedpacket >= 0:
            timeleft = int(round(timer - time.time(), 0))
            status("Received packets: %s, time left: %i  \r" % (str(i), timeleft))
            if receivedpacket == 0 or timeleft == 0:
                # PCAP networkstack timeout elapsed or regular timeout
                break
            rawdata = pkt_data[0:header.contents.len]
            packettype = hexlify(bytearray(rawdata[12:14])).lower()
            targetmac = hexlify(bytearray(rawdata[:6])).lower()
            if packettype == ethertype.lower() and srcmac.lower() == targetmac:
                #print('Succes! Found an ' + ethertype + ' packet                          ')
                receivedRawData.append(rawdata)
                if stopOnReceive: break

            ## Load next packet
            receivedpacket = pcap_next_ex(fp, byref(header), byref(pkt_data))
            i += 1
        pcap_close(fp)
        return receivedRawData

    ## Parsing the Raw PN_DCP data on discovery (source: https://code.google.com/p/scada-tools/source/browse/profinet_scanner.py)
    ## Returns type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway
    def parseResponse(data, mac):
        result = {}
        result['mac_address'] = mac
        result['type_of_station'] = 'None'
        result['name_of_station'] = 'None'
        result['vendor_id'] = 'None'
        result['device_id'] = 'None'
        result['device_role'] = 'None'
        result['ip_address'] = 'None'
        result['subnet_mask'] = 'None'
        result['standard_gateway'] = 'None'
        ## Since this is the parse of a DCP identify response, data should start with feff (Profinet FrameID 0xFEFF)
        if not str(data[:4]).lower() == 'feff':
            print('Error: this data is not a proper DCP response?')
            return result
        
        dataToParse = data[24:] # (Static) offset to where first block starts
        while len(dataToParse) > 0:
            ## Data is divided into blocks, where block length is set at byte 2 & 3 (so offset [4:8]) of the block
            blockLength = int(dataToParse[2*2:4*2], 16)
            block = dataToParse[:(4 + blockLength)*2]

            ## Parse the block
            blockID = str(block[:2*2])
            if blockID == '0201':
                result['type_of_station'] = str(unhexlify(block[4*2:4*2 + blockLength*2]))[2:]
            elif blockID == '0202':
                result['name_of_station'] = str(unhexlify(block[4*2:4*2 + blockLength*2]))[2:]
            elif blockID == '0203':
                result['vendor_id'] = str(block[6*2:8*2])
                result['device_id'] = str(block[8*2:10*2])
            elif blockID == '0204':
                result['device_role'] = str(block[6*2:7*2])
                devrole = ''
                
            elif blockID == '0102':
                result['ip_address'] = socket.inet_ntoa(struct.pack(">L", int(block[6*2:10*2], 16)))
                result['subnet_mask'] = socket.inet_ntoa(struct.pack(">L", int(block[10*2:14*2], 16)))
                result['standard_gateway'] = socket.inet_ntoa(struct.pack(">L", int(block[14*2:18*2], 16)))
            
            ## Maintain the loop
            padding = blockLength%2 # Will return 1 if odd
            dataToParse = dataToParse[(4 + blockLength + padding)*2:]
            
        return result
            
    def status(msg):
        sys.stderr.write(msg)
        sys.stderr.flush()

    def endIt(sMessage=''):
        print
        if sMessage: print('Error message: '+sMessage)
        print('All done')
        #raw_input('Press ENTER to continue')
        sys.exit()

    def scanPort(ip, port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1) # 1 second timeout
        try:
            sock.connect((ip, port))
            sock.close()
        except:
            return ''
        return port

    def tcpScan(device, scanOnly = False):
        openports = []
        if scanPort(device['ip_address'], 102) == 102:
            openports.append(102)
            if not scanOnly:
                s7.Scan(device['ip_address'], 102)
        if scanPort(device['ip_address'], 502) == 502:
            openports.append(502)
            if not scanOnly:
                modbus.Scan(device['ip_address'], 502)
        device['open_ports'] = openports
        return device

    def getInfo(device):
        #os.system('cls' if os.name == 'nt' else 'clear')
        # Try to parse id to a readable format (source: Wireshark)
        vendorid = 'Unknown ID'
        devid = 'Unknown ID'
        devrole = ''
        if device['vendor_id'] == '002a': vendorid = 'Siemens'
        if device['device_id'] == '0a01': devid = 'Switch'
        elif device['device_id'] == '0202': devid = 'PCSIM'
        elif device['device_id'] == '0203': devid = 'S7-300 CP'
        elif device['device_id'] == '0101': devid = 'S7-300'
        elif device['device_id'] == '010d': devid = 'S7-1200'
        elif device['device_id'] == '0301': devid = 'HMI'
        elif device['device_id'] == '010b': devid = 'ET200S'
        binresult = bin(int(device['device_role'], 16))[2:]
        if int(binresult) & 1 == 1: devrole += 'IO-Device '
        if int(binresult) & 10 == 10: devrole += 'IO-Controller '
        if int(binresult) & 100 == 100: devrole += 'IO-Multidevice '
        if int(binresult) & 1000 == 1000: devrole += 'PN-Supervisor '
        print('               ###--- DEVICE INFO ---###')
        print('--------- INFORMATION GATHERED THROUGH PN_CDP -------------')
        print('Mac Address:      ' + device['mac_address'])
        print('Type of station:  ' + device['type_of_station'])
        print('Name of station:  ' + device['name_of_station'])
        print('Vendor ID:        ' + device['vendor_id'] + ' (decoded: ' + vendorid + ')')
        print('Device ID:        ' + device['device_id'] + ' (decoded: ' + devid + ')')
        print('Device Role:      ' + device['device_role'] + '   (decoded: ' + devrole + ')')
        print('IP Address:       ' + device['ip_address'])
        print('Subnetmask:       ' + device['subnet_mask'])
        print('Standard Gateway: ' + device['standard_gateway'])
        print
        ## TCP port scan
        if s7present:
            print('------ INFORMATION GATHERED THROUGH TCPIP (plcscan) -------')
            device = tcpScan(device)
        else:
            print('------ INFORMATION GATHERED THROUGH TCPIP (DIRECT) --------')
            getInfoViaCOTP(device)
            print('')
            print(' --> CPU State: '+getCPU(device)+'\n')
        #raw_input('Press [Enter] to return to the menu')
        return device

    def isIpv4(ip):
        match = re.match("^(\d{0,3})\.(\d{0,3})\.(\d{0,3})\.(\d{0,3})$", ip)
        if not match:
            return False
        quad = []
        for number in match.groups():
            quad.append(int(number))
        if quad[0] < 1:
            return False
        for number in quad:
            if number > 255 or number < 0:
                    return False
        return True

    def setNetwork(device, npfdevice, srcmac):
        def ipToHex(ipstr):
            iphexstr = ''
            for s in ipstr.split('.'):
                if len(hex(int(s))[2:]) == 1:
                    iphexstr += '0'
                iphexstr += str(hex(int(s))[2:])
            return iphexstr
        
        #os.system('cls' if os.name == 'nt' else 'clear')
        print('      ###--- DEVICE NETWORK CONFIG ---###')
        newip = raw_input('Provide the new IP address ['+device['ip_address']+']     : ')
        if newip == '': newip = device['ip_address']
        newsnm = raw_input('Provide the new subnet mask ['+device['subnet_mask']+']    : ')
        if newsnm == '': newsnm = device['subnet_mask']
        newgw = raw_input('Provide the new standard gateway ['+device['standard_gateway']+']: ')
        if newgw == '': newgw = device['standard_gateway']
        if not isIpv4(newip) or not isIpv4(newsnm) or not isIpv4(newgw):
            print('One or more addresses were wrong. \nPlease go read RFC 791 and then use a legitimate IPv4 address.')
            raw_input('')
            return device
        networkdata = ipToHex(newip) + ipToHex(newsnm) + ipToHex(newgw)
        print('Hold on, crafting packet...')
        print

        ## First start a background capture to capture the reply
        scan_response = ''
        pool = ThreadPool(processes=1)
        async_result = pool.apply_async(receiveRawPackets, (npfdevice, 2, srcmac, '8892', True))
        time.sleep(1) # Give thread time to start

        ## Send packet
        sendRawPacket(npfdevice, '8892', srcmac, True, networkdata, device['mac_address'].replace(':', ''))

        ## Check if response is OK
        data = hexlify(bytearray(async_result.get()[0]))[28:]
        responsecode = str(data[36:40])
        if responsecode == '0000':
            print('Successfully set new networkdata!                     ')
            device['ip_address'] = newip
            device['subnet_mask'] = newsnm
            device['standard_gateway'] = newgw
        elif responsecode == '0600':
            print('Error setting networkdata: device in operation.       ')
        elif responsecode == '0300':
            print('Error setting networkdata: function not implemented.  ')
        else:
            print('Undefined response (' + responsecode + '), please investigate.        ')
        
        #raw_input('Press [Enter] to return to the device menu')
        return device

    def setStationName(device, npfdevice, srcmac):
        #os.system('cls' if os.name == 'nt' else 'clear')
        print('      ###--- DEVICE NETWORK CONFIG ---###')
        print('Attention: Only lower case letters and the \'-\' symbol are allowed!')
        newname = raw_input('Provide the new name ['+device['name_of_station']+']     : ')
        if newname == '': newname = device['name_of_station']
        
        ## First start a background capture to capture the reply
        scan_response = ''
        pool = ThreadPool(processes=1)
        async_result = pool.apply_async(receiveRawPackets, (npfdevice, 2, srcmac, '8892', True))
        time.sleep(1) # Give thread time to start

        ## Send packet length, PN_DCP SET (04), Request (00), DeviceName-Xid (02010004), Padding (0000), DCPLength (0012 or d18)
        ##  Device Properties (02), NameOfStation (02), DCPLength (000d or d13), BlockQualifier (0001), NameItself (11 byte), Padding (00)
        ##  Padding (to get to 60 bytes?)
        nname=hexlify(newname.lower())
        namelength=len(nname)/2
        padding = ''
        if namelength%2 == 1: padding = '00'
        firstDCP = hex(namelength+(len(padding)/2)+6)[2:]
        if len(firstDCP) == 1: firstDCP='000'+firstDCP
        if len(firstDCP) == 2: firstDCP='00'+firstDCP
        if len(firstDCP) == 3: firstDCP='0'+firstDCP
        secondDCP = hex(namelength+2)[2:]
        if len(secondDCP) == 1: secondDCP='000'+secondDCP
        if len(secondDCP) == 2: secondDCP='00'+secondDCP
        if len(secondDCP) == 3: secondDCP='0'+secondDCP
        data='fefd 04 00 02010004 0000'
        #data+='0012'## Change this (length of name+padding+5)
        data+=firstDCP
        data+='02 02'
        #data+='000d'## Change this (length of name)
        data+=secondDCP
        data+='0001'
        #data+='7869616b64656d6f706c63 00' #xiakdemoplc (11 characters), Change this
        data+=nname+padding
        data+='00000000000000000000000000000000' ## Padding to get to 60 bytes, Change this
        
        sendRawPacket(npfdevice, '8892', srcmac, False, data.replace(' ',''), device['mac_address'].replace(':', ''))

        ## Check if response is OK
        data = hexlify(bytearray(async_result.get()[0]))[28:]
        responsecode = str(data[36:38])
        if responsecode == '00':
            print('Successfully set new Station Name to '+newname)
            device['name_of_station']=newname
        elif responsecode == '03':
            print('Error setting Station Name: Name Not Accepted!')
            print(data)

        #raw_input('Press [Enter] to return to the device menu')
        return device

    def send_and_recv(sock, strdata, sendOnly = False):
        data = unhexlify(strdata.replace(' ','').lower()) ## Convert to real HEX (\x00\x00 ...)
        sock.send(data)
        if sendOnly: return
        ret = sock.recv(65000)
        return ret

    def getS7GetCoils(ip):
        def printData(sWhat, s7Response): ## Expects 4 byte hex data (e.g. 00000000)
            if not s7Response[18:20] == '00': finish('Some error occured with S7Comm Setup, full response: ' + str(s7Response) + '\n')
            s7Data = s7Response[14:]
            datalength = int(s7Data[16:20], 16) ## Normally 5 bytes for a byte, 6 if we request word, 8 if we request real
            s7Items = s7Data[28:28 + datalength*2]
            if not s7Items[:2] == 'ff': finish('Some error occured with S7Comm Data Read, full S7Comm data: ' + str(s7Data) + '\nFirmware not supported?\n')
        
            print('     ###--- ' + sWhat + ' ---###')
            sToShow = [''] * 8
            for i in range(0,4):
                iOffset1 = (4 - i) * -2
                iOffset2 = iOffset1 + 2
                if iOffset2 == 0: iOffset2 = None
                iData = int(s7Items[iOffset1:iOffset2], 16) ## Now we have e.g. 02, which is 00000010

                for j in range(0,8):
                    ## Performing binary and of the inputs AND 2^1 to get value of last bit
                    bVal = iData & int(2**j)
                    if not bVal == 0: bVal = 1
                    sToShow[j] = sToShow[j] +  str(i) + '.' + str(j) + ': ' + str(bVal) + ' | ' 
            for i in range(0,8): print(sToShow[i][:-2])
            print('')

        sock = setupConnection(ip, 102)

        ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last 24 bytes are S7Comm Read Var.
        ##   Request Byte (02) or Word (04) or Dword (06)
        ##   '81' means read inputs (I)
        ##   '000000' means starting at Address 0 (I think)
        
        ## Get Inputs in Dword (so 32 inputs) starting from Address 0
        s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 81 000000'.replace(' ','')))
        printData('Inputs',s7Response)

        ## Outputs (82)
        s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 82 000000'.replace(' ','')))
        printData('Outputs',s7Response)

        ## Merkers (83)
        s7Response = hexlify(send_and_recv(sock, '0300001f' + '02f080' + '32010000732f000e00000401120a10 06 00010000 83 000000'.replace(' ','')))
        printData('Merkers',s7Response)
        sock.close()

    def setupConnection(sIP, iPort):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((sIP, iPort))
        ## Always start with a COTP CR (Connection Request), we need a CS (Connection Success) back
        cotpsync = hexlify(send_and_recv(sock, '03000016' + '11e00000000100c0010ac1020100c2020101'))
        if not cotpsync[10:12] == 'd0': finish('COTP Sync failed, PLC not reachable?')
        ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last 18 bytes are S7Comm Setup Communication
        s7comsetup = hexlify(send_and_recv(sock, '03000019' + '02f080' + '32010000722f00080000f0000001000101e0'))
        if not s7comsetup[18:20] == '00': finish('Some error occured with S7Comm setup, full data: ' + s7comsetup)
        return sock

    def setOutputs(sIP, iPort, sOutputs):
        if sOutputs == '' or len(sOutputs) > 8: sOutputs = '0'
        ## Outputs need to be reversed before sending: ('11001000' must become '00010011')
        sOutputs = sOutputs[::-1]
        ## Converted to hexstring ('00010011' becomes '13')
        hexstring = hex(int(sOutputs, 2))[2:]
        if len(hexstring) == 1: hexstring = '0' + hexstring # Add leading zero
        
        ## Setup the connection
        sock = setupConnection(sIP, iPort)

        ## Set Outputs
        ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last 24 bytes are S7Comm Set Var, last byte contains data to send!
        s7Response = hexlify(send_and_recv(sock, '03000024' + '02f080' + '32010000732f000e00050501120a1002000100008200000000040008' + hexstring))
        if s7Response[-2:] == 'ff': print('Writing Outputs successful')
        else: print('Error writing outputs.')
        sock.close()

    def setMerkers(sIP, iPort, sMerkers, iMerkerOffset=0):
        ## Outputs need to be reversed before sending: ('11001000' must become '00010011')
        sMerkers = sMerkers[::-1]
        ## Converted to hexstring ('00010011' becomes '13')
        hexstring = hex(int(sMerkers, 2))[2:]
        if len(hexstring) == 1: hexstring = '0' + hexstring # Add leading zero
        
        ## Setup the connection
        sock = setupConnection(sIP, iPort)

        ## Set Merkers
        ## First 4 bytes are TPKT (last byte==datalength), next 3 bytes are COTP, last bytes are S7Comm Write Var, '83' is Merker, last bytes contain data to send!
        # '320100000800000e00080501120a1006000100008300000000040020 00070000'
        ## '83' is merkers
        ## '000000' is address (address 9 = 000048 => '1001' + '000' = 0100 1000 = 0x48)
        ## 04 is WORD (so 2 bytes in the end)
        
        ## Convert iMerkerOffset to BIN, add '000' and convert back to HEX
        sMerkerOffset = bin(iMerkerOffset)
        sMerkerOffset = sMerkerOffset + '000'
        hMerkerOffset = str(hex(int(sMerkerOffset[2:],2)))[2:]
        hMerkerOffset = hMerkerOffset.zfill(6) ## Add leading zero's up to 6
        print('Sending '+hexstring+' using offset '+hMerkerOffset)

        s7Response = hexlify(send_and_recv(sock, '03000025' + '02f080' + '320100001500000e00060501120a100400010000 83 ' + hMerkerOffset + '00 04 0010' + hexstring + '00'))
        if s7Response[-2:] == 'ff': print('Writing Merkers successful')
        else: print('Error writing merkers.')
        sock.close()

    def manageOutputs1(device):
        status = ''

        ports = []
        #os.system('cls' if os.name == 'nt' else 'clear')
        print('      ###--- Manage Outputs ---###')
        if status != '':
            print('## --> ' + status)
            status = ''
        print
        try:
            ports = device['open_ports']
        except:
            print('Scanning the device first.')
            device = tcpScan(device, True)
            ports = device['open_ports']
        if len(ports) == 0: return 1
        for port in ports:
            if port == 102:
                print('S7Comm (Siemens) detected, getting outputs...')
                getS7GetCoils(device['ip_address'])
            else: return 1
        #raw_input('Press [Enter] to return to the device menu')

    def changeOutputs(device,arr_tmp):
        status = ''

        ports = []
        #os.system('cls' if os.name == 'nt' else 'clear')
        print('      ###--- Manage Outputs ---###')
        if status != '':
            print('## --> ' + status)
            status = ''
        print
        try:
            ports = device['open_ports']
        except:
            print('Scanning the device first.')
            device = tcpScan(device, True)
            ports = device['open_ports']
        if len(ports) == 0: return 1
        for port in ports:
            if port == 102:
                print('S7Comm (Siemens) detected, getting outputs...')
                setOutputs(device['ip_address'], 102, arr_tmp)
                getS7GetCoils(device['ip_address'])
                status = 'Output has been send to device, verifying results: '
            else: return 1
        #raw_input('Press [Enter] to return to the device menu')

    def flashLED(npf, device, srcmac, duration):
        print("x"*20)
        print(npf,device['name_of_station'],srcmac,device['mac_address'])
        print("x"*20)

        runLoop = True
        i = 0
        while runLoop:
            #os.system('cls' if os.name == 'nt' else 'clear')
            print('     ###--- Flashing LED ---###')
            print('Flashing LED of '+device['name_of_station']+', '+str(i)+' out of '+str(duration)+ ' seconds.')

            ## Send packet (length, PN_DCP SET (04), Request (00), LED-Xid (00001912), DCPLength (8), Control (5), Signal (3), DCPLength (4), Undecoded (0100)
            data='fefd 040000001912000000080503000400000100 000000000000000000000000000000000000000000000000000000000000'
            sendRawPacket(npf, '8892', srcmac, False, data.replace(' ',''), device['mac_address'].replace(':', ''))
            
            i+=2
            if i > duration:
                runLoop = False
            time.sleep(2)
            
            
    def getInfoViaCOTP(device):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1) # 1 second timeout
        sock.connect((device['ip_address'], 102)) ## Will setup TCP/SYN with port 102
        cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000000500c1020600c2020600c0010a'))
        if not cotpconnectresponse[10:12] == 'd0':
            print('COTP Connection Request failed, no route to IP '+device['ip_address']+'?')
            return []

        data = '720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f3742363743433341a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a304a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'
        tpktlength = str(hex((len(data)+14)/2))[2:] ## Dynamically find out the data length
        cotpdata = send_and_recv(sock, '030000'+tpktlength+'02f080'+data)

        ## It is sure that the CPU state is NOT in this response
        print('Hardware: '+cotpdata.split(';')[2])
        print('Firmware: '+filter(lambda x: x in string.printable, cotpdata.split(';')[3].replace('@','.')))

        sock.close()

    def manageCPU(device):
        runLoop = True

        #os.system('cls' if os.name == 'nt' else 'clear')
        print('     ###--- Manage CPU ---###\n')
        print('Current CPU state: '+getCPU(device))
        print('This will take some seconds ...')
        changeCPU(device)

            

    def getCPU(device):
        sState = 'Running'
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1) # 1 second timeout
        sock.connect((device['ip_address'], 102)) ## Will setup TCP/SYN with port 102
        # Firstly: the COTP Connection Request (CR), should result in Connection Confirm (CC)
        ## TPKT header + COTP CR TPDU with src-ref 0x0005 (gets response with dst-ref 0x0005)
        cotpconnectresponse = hexlify(send_and_recv(sock, '03000016'+'11e00000001d00c1020100c2020100c0010a'))
        ## Response should be 03000016 11d00005001000c0010ac1020600c2020600
        if not cotpconnectresponse[10:12] == 'd0':
            print('COTP Connection Request failed')
            return
        ##---- S7 Setup Comm ------------
        ## TPKT header + COTP header + S7 data (which is: Header -Job- + Parameter -Setup-)
        s7setupdata='32010000020000080000'+'f0000001000101e0'
        tpktlength = str(hex((len(s7setupdata)+14)/2))[2:]
        s7setup = send_and_recv(sock, '030000'+tpktlength+'02f080'+s7setupdata)
        ##---- S7 Request CPU -----------
        s7readdata = '3207000005000008 000800011204 11440100ff09000404240001'
        tpktlength = str(hex((len(s7readdata.replace(' ',''))+14)/2))[2:]
        s7read = send_and_recv(sock,'030000'+tpktlength+'02f080'+s7readdata)
        if hexlify(s7read[44:45]) == '03': sState = 'Stopped'
        sock.close()
        return sState

    def changeCPU(device):
        curState = getCPU(device)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((device['ip_address'], 102)) ## Will setup TCP/SYN with port 102
        ## CR TPDU
        send_and_recv(sock,'03000016'+'11e00000002500c1020600c2020600c0010a')
        ## 'SubscriptionContainer'
        sResp = hexlify(send_and_recv(sock,'030000c0'+'02f080'+'720100b131000004ca0000000200000120360000011d00040000000000a1000000d3821f0000a3816900151653657276657253657373696f6e5f4536463534383534a3822100150b313a3a3a362e303a3a3a12a3822800150d4f4d532b204465627567676572a38229001500a3822a001500a3822b00048480808000a3822c001211e1a300a3822d001500a1000000d3817f0000a38169001515537562736372697074696f6e436f6e7461696e6572a2a20000000072010000'))
        sSID = str(hex(int(sResp[48:50],16)+int('80',16))).replace('0x','')
        if curState == 'Stopped': ## Will perform start
            send_and_recv(sock,'03000078'+'02f080'+'72020069310000054200000003000003'+sSID+'34000003 ce 010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b313035388241000300030000000004e88969001200000000896a001300896b000400000000000072020000')
        else:
            send_and_recv(sock,'03000078'+'02f080'+'72020069310000054200000003000003'+sSID+'34000003 88 010182320100170000013a823b00048140823c00048140823d000400823e00048480c040823f0015008240001506323b313035388241000300030000000004e88969001200000000896a001300896b000400000000000072020000')
        send_and_recv(sock,'0300002b'+'02f080'+'7202001c31000004bb00000005000003'+sSID+'34000000010000000000000000000072020000')
        send_and_recv(sock,'0300002b'+'02f080'+'7202001c31000004bb00000006000003'+sSID+'34000000020001010000000000000072020000')
        runloop = True
        print('--- Getting data ---')
        while runloop:
            try: response = sock.recv(65000)
            except: runloop = False
        send_and_recv(sock,'03000042'+'02f080'+'7202003331000004fc00000007000003'+sSID+'360000003402913d9b1e000004e88969001200000000896a001300896b00040000000000000072020000')
        if curState == 'Stopped': ## Will perform start
            send_and_recv(sock,'03000043'+'02f080'+'7202003431000004f200000008000003'+sSID+'36000000340190770008 03 000004e88969001200000000896a001300896b00040000000000000072020000')
        else:
            send_and_recv(sock,'03000043'+'02f080'+'7202003431000004f200000008000003'+sSID+'36000000340190770008 01 000004e88969001200000000896a001300896b00040000000000000072020000')
        send_and_recv(sock,'0300003d'+'02f080'+'7202002e31000004d40000000a000003'+sSID+'34000003d000000004e88969001200000000896a001300896b000400000000000072020000')
        
        sock.close()
        return

    def getMac(ip, iface):
        ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip),timeout=2, iface=iface)
        for s,r in ans:
            return r[Ether].src