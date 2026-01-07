from .modbus_structure import (
    ModbusHeaderRequest, ModbusHeaderResponse,
    ReadCoilsRequest, ReadDiscreteInputsRequest,
    ReadHoldingRegistersRequest, ReadInputRegistersRequest,
    WriteSingleCoilRequest, WriteSingleRegisterRequest,
    WriteMultipleCoilsRequest, WriteMultipleRegistersRequest,
    MaskWriteRegisterRequest, ReadWriteMultipleRegistersRequest,
    ReadFileRecordRequest, WriteFileRecordRequest, ReadFIFOQueueRequest
)
import socket

class Modbus():
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.pdu = None
        self.data = None
        self.length = 0
        self.adu = None
        self.connection = None
        self.target = None
        self.port = None
        self.timeout = 5

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

    def read_coils(self, target, port, count, start_address, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x01) / ReadCoilsRequest(
            ReferenceNumber=start_address,
            BitCount=count
        )
        
        self.send_packet(request)
        response = self.receive_packet()
        parsed_response = ModbusHeaderResponse(response)
        
        if parsed_response.func_code == 0x01:
            coils_status = parsed_response.payload.CoilsStatus
            print(f"Coils Status: {coils_status}")
            self.close_connection()
            return coils_status
        else:
            print("Error in the response")
            return None
    
    def write_coil(self, target, port, address, value, timeout=5):
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
    
    def write_multiple_coils(self, target, port, start_address, values, timeout=5):
        self.init_connection(target, port, timeout)
        
        request = ModbusHeaderRequest(func_code=0x0F) / WriteMultipleCoilsRequest(
            ReferenceNumber=start_address,
            BitCount=len(values),
            CoilValues=values
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
            WordCount=len(values),
            RegisterValues=values
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