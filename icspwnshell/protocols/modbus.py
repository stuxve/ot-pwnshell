from .modbus_structure import (
    ModbusHeaderRequest, ModbusHeaderResponse,
    ReadCoilsRequest, ReadDeviceIdentificationRequest, ReadDeviceIdentificationResponse, ReadDiscreteInputsRequest,
    ReadHoldingRegistersRequest, ReadInputRegistersRequest,
    WriteSingleCoilRequest, WriteSingleRegisterRequest,
    WriteMultipleCoilsRequest, WriteMultipleRegistersRequest,
    MaskWriteRegisterRequest, ReadWriteMultipleRegistersRequest,
    ReadFileRecordRequest, WriteFileRecordRequest, ReadFIFOQueueRequest
)
import socket
import struct
import re
class Modbus():
    def __init__(self, target=None, port=None, timeout=5):
        self.pdu = None
        self.data = None
        self.length = 0
        self.adu = None
        self.connection = None
        self.target = target
        self.port = port
        self.timeout = 5
        self.trans_id = 1

    def close_connection(self):
        if self.connection:
            self.connection.close()
            self.connection = None

    def init_connection(self, target, port, timeout=5):
        if self.connection is None:
            self.target = target
            self.port = port
            self.timeout = timeout
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.settimeout(self.timeout)
            self.connection.connect((self.target, self.port))
    def read_coils(self, count, start_address):
        self.init_connection(self.target, self.port, self.timeout)
        
        request = ModbusHeaderRequest(func_code=0x01) / ReadCoilsRequest(
            ReferenceNumber=start_address,
            BitCount=count
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x01:
            coils_status = parsed_response.payload.CoilsStatus
            print(f"[+] Coils Status: {coils_status}")
            self.close_connection()
            return coils_status
        else:
            print("Error in the response")
            return None
    
    def write_single_coil(self, target, port, address, value, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x05) / WriteSingleCoilRequest(
            ReferenceNumber=address,
            Value=value
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x05:
            print(f"Write coil successful at address {address}")
            return parsed_response
        else:
            print("Error in the response")
            return None

    def read_discrete_input(self, target, port, count, start_address, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x02) / ReadDiscreteInputsRequest(
            ReferenceNumber=start_address,
            BitCount=count
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x02:
            inputs_status = parsed_response.payload.InputStatus
            print(f"Discrete Inputs Status: {inputs_status}")
            return inputs_status
        else:
            print("Error in the response")
            return None
    
    def read_holding_register(self, target, port, count, start_address, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x03) / ReadHoldingRegistersRequest(
            ReferenceNumber=start_address,
            WordCount=count
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x03:
            registers = parsed_response.payload.RegisterValue
            print(f"Holding Registers: {registers}")
            return registers
        else:
            print("Error in the response")
            return None
    
    def read_input_registers(self, target, port, count, start_address, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x04) / ReadInputRegistersRequest(
            ReferenceNumber=start_address,
            WordCount=count
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x04:
            registers = parsed_response.payload.RegisterValue
            print(f"Input Registers: {registers}")
            return registers
        else:
            print("Error in the response")
            return None
    
    def write_single_register(self, target, port, address, value, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x06) / WriteSingleRegisterRequest(
            ReferenceNumber=address,
            Value=value
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x06:
            print(f"Write register successful at address {address}")
            return parsed_response
        else:
            print("Error in the response")
            return None
    
    def write_multiple_coils(self, target, port, start_address, values, bit_count, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x0F) / WriteMultipleCoilsRequest(
            ReferenceNumber=start_address,
            BitCount=bit_count,
            Coils=values
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x0F:
            print(f"Write multiple coils successful starting at {start_address}")
            return parsed_response
        else:
            print("Error in the response")
            return None
    
    def write_multiple_registers(self, target, port, start_address, values, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x10) / WriteMultipleRegistersRequest(
            ReferenceNumber=start_address,
            #WordCount=len(values),
            RegistersValues=values
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x10:
            print(f"Write multiple registers successful starting at {start_address}")
            return parsed_response
        else:
            print("Error in the response")
            return None
    
    def mask_write_register(self, target, port, address, and_mask, or_mask, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x16) / MaskWriteRegisterRequest(
            ReferenceNumber=address,
            AndMask=and_mask,
            OrMask=or_mask
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x16:
            print(f"Mask write register successful at address {address}")
            return parsed_response
        else:
            print("Error in the response")
            return None
    
  
  
    def read_multiple_registers(self, target, port, read_start_address, read_count, write_start_address, write_values, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x17) / ReadWriteMultipleRegistersRequest(
            ReadReferenceNumber=read_start_address,
            ReadWordCount=read_count,
            WriteReferenceNumber=write_start_address,
            WriteWordCount=len(write_values),
            WriteRegisterValues=write_values
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x17:
            read_registers = parsed_response.payload.ReadRegisterValues
            print(f"Read/Write Multiple Registers - Read Values: {read_registers}")
            return read_registers
        else:
            print("Error in the response")
            return None
    
    
    def read_fifo_queue(self, target, port, fifo_pointer_address, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x18) / ReadFIFOQueueRequest(
            FIFOPointerAddress=fifo_pointer_address
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x18:
            fifo_values = parsed_response.payload.FIFOValue
            print(f"FIFO Queue: {fifo_values}")
            return fifo_values
        else:
            print("Error in the response")
            return None
        

    def parse_device_id_objects(self, raw_bytes):
        objects = []
        offset = 0

        while offset + 2 <= len(raw_bytes):
            obj_id = raw_bytes[offset]
            obj_len = raw_bytes[offset + 1]

            start = offset + 2
            end = start + obj_len

            if end > len(raw_bytes):
                break

            value = raw_bytes[start:end]
            objects.append((obj_id, value))

            offset = end

        return objects
    
    def build_pkt(self, unit_id, func_code, payload):
        """Builds a Modbus TCP/UMAS Frame."""
        length = 2 + len(payload)
        header = struct.pack(">HHHB", self.trans_id, 0, length, unit_id)
        self.trans_id += 1
        return header + struct.pack("B", func_code) + payload

    def send_and_recv(self, sock, func_code, payload):
        pkt = self.build_pkt(0, func_code, payload)
        sock.send(pkt)
        return sock.recv(2048)
    def unpack_z(self, buf, offset):
        end = buf.find(b"\x00", offset)
        if end == -1:
            return ""
        return buf[offset:end].decode(errors="ignore")
    def schneider_modicon_info(self, target, port, timeout=5):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        data = {
            "vendor": "", "net": "", "cpu": "", "fw": "", "mem": "",
            "proj_info": "", "rev": "", "mod": ""
        }

        try:
            sock.connect((target, port))

            # 1. Hardware Info (Function 43)
            res43 = self.send_and_recv(sock, 0x2B, b"\x0E\x03\x00")
            if len(res43) > 10:
                data["vendor"] = res43[16:36].decode(errors="ignore").strip()
                data["net"] = res43[38:50].decode(errors="ignore").strip()
                data["fw"] = res43[52:56].decode(errors="ignore").strip()

            # 2. UMAS CPU Discovery (Function 90 / Code 0x02)
            res_cpu = self.send_and_recv(sock, 0x5A, b"\x00\x02") 
            if len(res_cpu) > 32:
                # CPU Module string usually starts at 33
                data["cpu"] = res_cpu[32:].split(b'\x00')[0].decode(errors="ignore").strip()
            
            # 3. Memory Card Discovery (Function 90 / Code 0x06 0x06)
            # This is the specific "Messi" fix for the Memory Card
            res_mem = self.send_and_recv(sock, 0x5A, b"\x00\x06\x06")
            if len(res_mem) > 17:
                # The card string usually starts at index 17
                data["mem"] = res_mem[17:].split(b'\x00')[0].decode(errors="ignore").strip()
            
            # 4. UMAS Handshake & Session Poking
            self.send_and_recv(sock, 0x5A, b"\x00\x01\x00") 
            self.send_and_recv(sock, 0x5A, b"\x00\xFE\x00" + (b"\x54" * 249))

            # 5. Project Metadata (UMAS 0x03) - Date and Revision
            res_proj = self.send_and_recv(sock, 0x5A, b"\x00\x03\x00")
            if len(res_proj) > 47:
                s, m, h, d, M, y = struct.unpack("<BBBBBH", res_proj[37:44])
                data["mod"] = f"{M}/{d}/{y} {h:02}:{m:02}:{s:02}"
                r1, r2, r3 = struct.unpack("BBB", res_proj[44:47])
                data["rev"] = f"{r3}.{r2}.{r1}"

            # 6. Full Project Info (UMAS 0x20) - Extended strings
            res_ext = self.send_and_recv(sock, 0x5A, b"\x00\x20\x00\x14\x00\x64\x00\x00\x00\xf6\x00")
            project_info = ""

            if res_ext and len(res_ext) > 200:
                size = res_ext[6]              # same as NSE
                start = 180                    # Schneider fixed offset
                end = min(size + 6, len(res_ext))

                for pos in range(start, end):
                    b = res_ext[pos:pos+1]
                    if b == b"\x00":
                        project_info += " "
                    else:
                        project_info += b.decode(errors="ignore")

                project_info = project_info.strip()

            data["proj_info"] = project_info
            # Use regex to find all strings in the memory block
            #strings = re.findall(b"[\x20-\x7E]{3,}", res_ext[10:])
            #decoded_strings = [s.decode(errors='ignore').strip() for s in strings]
            #parse the different headers of unity modicon
            
            #res_ext = res_ext[9:]  # Skip the Modbus TCP header (first 9 bytes)
            

            #strings = res_ext[100:]
            #decoded_string = strings.decode(errors='ignore').strip()
            #parts = [s.strip() for s in decoded_string.split('\x00') if s.strip()]

            # 4. Remove duplicates while maintaining order
            #unique_parts = list(dict.fromkeys(parts))
            #data["proj_info"] = " ".join(unique_parts)

            # Filter out strings that are hardware identifiers to isolate Project info
            #filtered = [s for s in decoded_strings if s not in [data['vendor'], data['cpu'], data['fw']]]
            #if len(filtered) >= 2:
            #    data["proj_info"] = f"{filtered[0]}   {filtered[1]}   {filtered[2] if len(filtered)>2 else ''}".strip()
            #elif len(filtered) == 1:
            #    data["proj_info"] = filtered[0]

            return data

        except Exception as e:
            return f"Error: {e}"
        finally:
            sock.close()
    def read_device_identification(self, target, port, timeout=5):
        self.init_connection(target, port, timeout)

        request = (
            ModbusHeaderRequest(func_code=0x2B) /
            ReadDeviceIdentificationRequest()
        )

        self.send_packet(request)
        response = self.receive_packet()
        self.close_connection()

        parsed_response = ModbusHeaderResponse(response)

        # --- Modbus exception handling ---
        if parsed_response.func_code & 0x80:
            print("Modbus exception response")
            return None

        if parsed_response.func_code != 0x2B:
            print("Unexpected function code")
            return None
        DEVICE_ID_OBJECT_NAMES = {
            0x00: "VendorName",
            0x01: "ProductCode",
            0x02: "MajorMinorRevision",
            0x03: "VendorUrl",
            0x04: "ProductName",
            0x05: "ModelName",
            0x06: "UserApplicationName",
        }
        # raw_pdu is already defined as:
        raw_pdu = parsed_response.payload.load

        # Extract fields from the MEI 0x0E response
        conformity_level = raw_pdu[3]
        more_follows = bool(raw_pdu[4])
        num_objects = raw_pdu[5]

        # Parse objects
        raw_objects = raw_pdu[6:]
        objects = self.parse_device_id_objects(raw_objects)

        result = {
            "conformity_level": conformity_level,
            "more_follows": more_follows,
            "objects": {}
        }

        for obj_id, raw_val in objects:
            value = raw_val.decode(errors="ignore")
            #print(f"Object ID: {obj_id}")
            #print(f"Value: {value}")
            obj_name = DEVICE_ID_OBJECT_NAMES.get(obj_id, f"Unknown_{obj_id}")
            result["objects"][obj_name] = value

        return result
        
    def send_packet(self, packet):
        self.connection.send(bytes(packet))

    def receive_packet(self):
        response = self.connection.recv(1024)
        return response
    
    def parse_packet(self, raw_packet):
        try:
            packet = ModbusHeaderRequest(raw_packet)
            payload_class = packet.guess_payload_class(raw_packet[7:])
            if payload_class:
                packet = packet / payload_class(raw_packet[7:])
            return packet
        except Exception as e:
            print(f"Error parsing packet: {e}")
            return None