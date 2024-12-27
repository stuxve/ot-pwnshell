







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


https://datapoint.uk/2015/03/modbus-tcpip-part-1/
https://pymodbustcp.readthedocs.io/en/latest/examples/client_write_coils.html
https://books.spartan-cybersec.com/cpics/herramientas-y-tecnicas/inyeccion-maliciosa-de-comandos-modbus/utilizando-python




https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/s7comm.md



https://github.com/dark-lbp/isf/blob/master/icssploit/modules/exploits/plcs/siemens/s7_1200_plc_control.py