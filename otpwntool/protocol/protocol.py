## Create an abstract class for a protocol, craft a packet with scappy and sand the packet. Use pwntools to send the packet to the server and receive the response.
## Also the functions of the abstract class will be create packets and send the packet.
## The class will be called Protocol and will have the following functions:
## - create_packet: This function will be used to create the packet with scapy.
## - send_packet: This function will be used to send the packet to the server.
## - receive_packet: This function will be used to receive the response from the server.
## - send_receive: This function will be used to send the packet and receive the response.
## - send_receive_repeat: This function will be used to send the packet and receive the response multiple times.
## - send_receive_until: This function will be used to send the packet and receive the response until a condition is met.
## - send_receive_repeat_until: This function will be used to send the packet and receive the response multiple times until a condition is met.
## - send_receive_until_timeout: This function will be used to send the packet and receive the response until a condition is met or a timeout is reached.



class Protocol:
    def __init__(self, target, port, timeout=5):
        self.target = target
        self.port = port
        self.timeout = timeout
        self.packet = None
        self.response = None

    def create_packet(self):
        pass

    def send_packet(self):
        pass

    def receive_packet(self):
        pass

    def send_receive(self):
        pass

    #def send_receive_repeat(self):
        pass

    #def send_receive_until(self):
        pass

    #def send_receive_repeat_until(self):
        pass

    #def send_receive_until_timeout(self):
        pass