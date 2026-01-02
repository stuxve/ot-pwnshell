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

    #def receive_packet(self):
    #    pass

    def send_receive(self):
        pass

    #def send_receive_repeat(self):
    #    pass

    #def send_receive_until(self):
    #    pass

    #def send_receive_repeat_until(self):
    #    pass

    #def send_receive_until_timeout(self):
    #    pass