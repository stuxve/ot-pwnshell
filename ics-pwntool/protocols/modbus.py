from .modbus_structure import *
class Modbus():
    def __init__ (self, **kwargs):
        super().__init__(**kwargs)
        #self.unit_id = 1
        #self.transaction_id = 1
       # self.protocol_id = 0
        #self.function_code = 0
        #self.error = None
        #self.error_code = None
        #self.error_message = None
        #self.exception_code = None
        #self.exception_message = None
        #self.response = None
        self.pdu = None
        self.data = None
        self.length = 0
        self.adu = None
        #self.error = None
        #self.error_code = None
        #self.error_message = None
        #self.exception_code = None
        #self.exception_message = None
        #self.data = None
    

    def read_coil(self):

        # Crear el paquete de solicitud
        request = ModbusHeaderRequest(func_code=0x01) / ReadCoilsRequest(ReferenceNumber=0x0000, BitCount=0x0010)
        
        ##Parse packet
        #try:
            #packet = ModbusHeaderRequest(request)
            #payload_class = packet.guess_payload_class(request[7:])
            #if payload_class:
                #packet = packet / payload_class(request[7:])
            #return packet
        #except Exception:
            #print("Error al analizar el paquete, paquete")
            #return


        # Enviar el paquete (esto es un ejemplo, debes reemplazarlo con tu método de envío)
        self.send_packet(request)
        
        # Recibir el paquete de respuesta (esto es un ejemplo, debes reemplazarlo con tu método de recepción)
        response = self.receive_packet()
        
        # Analizar el paquete de respuesta
        parsed_response = ModbusHeaderResponse(response)
        
        # Procesar la respuesta
        if parsed_response.func_code == 0x01:
            coils_status = parsed_response.payload.CoilsStatus
            print(f"Coils Status: {coils_status}")
        else:
            print("Error en la respuesta")
    
    def write_coil(self):
        self.function_code = 0x05
        self.pdu = WriteSingleCoilRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    

    def read_discrete_input(self):
        self.function_code = 0x02
        self.pdu = ReadDiscreteInputsRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def read_holding_register(self):
        self.function_code = 0x03
        self.pdu = ReadHoldingRegistersRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def read_input_register(self):
        self.function_code = 0x04
        self.pdu = ReadInputRegistersRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def write_single_register(self):
        self.function_code = 0x06
        self.pdu = WriteSingleRegisterRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def write_multiple_coils(self):
        self.function_code = 0x0F
        self.pdu = WriteMultipleCoilsRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def write_multiple_registers(self):
        self.function_code = 0x10
        self.pdu = WriteMultipleRegistersRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def mask_write_register(self):
        self.function_code = 0x16
        self.pdu = MaskWriteRegisterRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def read_write_multiple_registers(self):
        self.function_code = 0x17
        self.pdu = ReadWriteMultipleRegistersRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def read_file_record(self):
        self.function_code = 0x14
        self.pdu = ReadFileRecordRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def write_file_record(self):
        self.function_code = 0x15
        self.pdu = WriteFileRecordRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def read_fifo_queue(self):
        self.function_code = 0x18
        self.pdu = ReadFIFOQueueRequest()
        self.data = self.pdu
        self.length = len(self.data)
        self.adu = ModbusHeaderRequest

        # Send packet
        self.send_packet()
        self.receive_packet()
        self.parse_packet()
    
    def send_packet(self, packet):
        # Convertir el paquete a bytes y enviarlo
        self.connection.send(bytes(packet))

    def receive_packet(self):
        # Recibir la respuesta del servidor
        response = self.connection.recv()
        return response
def parse_packet(raw_packet):
    # Intentar analizar como ModbusHeaderRequest
    try:
        packet = ModbusHeaderRequest(raw_packet)
        payload_class = packet.guess_payload_class(raw_packet[7:])
        if payload_class:
            packet = packet / payload_class(raw_packet[7:])
        return packet
    except Exception:
        print("Error al analizar el paquete, paquete")

    return None