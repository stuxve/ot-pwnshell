
!!Not tested!!

S7comm STOP:
```
python command_sender.py --protocol s7 --target-ip 192.168.0.100 --target-port 102 --action stop
```

Modbus TCP START:
```
python command_sender.py --protocol modbus --target-ip 192.168.0.101 --target-port 502 --action start
```
OPC UA START:
```
python command_sender.py --protocol opcua --endpoint opc.tcp://192.168.0.102:4840 --action start
```