# ICS PWNSHELL

> **Interactive shell for offensive research and testing of Industrial Control Systems (ICS).**

ICS PWNSHELL is a lightweight, extensible CLI designed to help security researchers, red teamers, and ICS enthusiasts explore, test, and *pwn* industrial protocols in a controlled and authorized environment.

⚠️ **Disclaimer**: This tool is intended **only** for educational purposes, labs, and systems you own or have explicit permission to test. Do **not** use it against production or unauthorized environments.

---

## ✨ Features

* Interactive shell inspired by classic exploitation frameworks
* Modular protocol-oriented design
* Focused on real-world ICS/OT protocols
* Easy to extend with new modules and commands
* Built with Python for rapid research and prototyping

---

## 📦 Installation

Make sure you have Python 3.9+ installed.

```bash
pip3 install -r requirements
```

(Optional but recommended: use a virtual environment.)

---

## 🚀 Usage

Launch the shell with:

```bash
python -m icspwnshell.main
```

Once inside, use `help` to explore available commands and protocols.


---

## 🧠 Roadmap / TODO

Planned and in-progress features:

* [X] 0x01 Read Coils (Modbus)
* [X] 0x02 Read Discrete Inputs (Modbus)
* [X] 0x03 Read Holding Registers (Modbus)
* [X] 0x04 Read Input Registers (Modbus)
* [ ] 0x05 Write Single Coil (Modbus)
* [ ] 0x06 Write Single Register (Modbus)
* [ ] 0x0F Write Multiple Coils (Modbus)
* [ ] 0x10 Write Multiple Registers (Modbus)
* [ ] Modbus banner grabbing
* [ ] Advanced Modbus functions
* [ ] Profinet device discovery
* [ ] Siemens S7 client connection (`whoami`-style info)
* [ ] Improved module auto-completion
* [ ] More ICS protocol support

Contributions and ideas are welcome 👀

---

## 📚 Research & References

This project is heavily inspired by public research and community knowledge:

* Modbus TCP/IP overview  
  [https://datapoint.uk/2015/03/modbus-tcpip-part-1/](https://datapoint.uk/2015/03/modbus-tcpip-part-1/)

* PyModbusTCP examples  
  [https://pymodbustcp.readthedocs.io/en/latest/examples/client_write_coils.html](https://pymodbustcp.readthedocs.io/en/latest/examples/client_write_coils.html)

* Modbus command injection with Python (ES)  
  [https://books.spartan-cybersec.com/cpics/herramientas-y-tecnicas/inyeccion-maliciosa-de-comandos-modbus/utilizando-python](https://books.spartan-cybersec.com/cpics/herramientas-y-tecnicas/inyeccion-maliciosa-de-comandos-modbus/utilizando-python)

* Awesome Industrial Protocols (S7, Profinet, more)  
  [https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/s7comm.md](https://github.com/Orange-Cyberdefense/awesome-industrial-protocols/blob/main/protocols/s7comm.md)

* ICSsploit S7-1200 module  
  [https://github.com/dark-lbp/isf/blob/master/icssploit/modules/exploits/plcs/siemens/s7_1200_plc_control.py](https://github.com/dark-lbp/isf/blob/master/icssploit/modules/exploits/plcs/siemens/s7_1200_plc_control.py)

---
## Data Structures

### Coils

- Size: 1 bit (ON / OFF)

- Access: Read and write

- Typical use: Digital actuators

#### Examples

- Start / stop a motor

- Open / close a valve

- Activate a relay



Think of them as buttons or switches

### Discrete Inputs

- Size: 1 bit

- Access: Read-only

- Typical use: Digital sensors

#### Examples

- Limit switch

- Presence sensor

- Contact status

They are like LEDs you can only observe

### Input Registers

- Size: 16 bits (2 bytes)

- Access: Read-only

- Typical use: Analog measurements

#### Examples

- Temperature

- Pressure

- Voltage

- Current

### Holding Registers

- Size: 16 bits

- Access: Read and write

- Typical use: Configuration and setpoints

#### Examples

- Temperature setpoint

- Motor speed

- PLC parameters

- Counters
---
## ☕ Support the Project

If you find **ICS PWNSHELL** useful and want to support ongoing research and development, you can buy me a coffee:

👉 **Buy Me a Coffee**: [https://buymeacoffee.com/stuxve](https://buymeacoffee.com/stuxve)

Every coffee helps keep the research going ❤️

---

## License
This program is free software: you can redistribute it and/or modify it under the terms of the MIT License.

You should have received a copy of the MIT License along with this program. If not, see https://opensource.org/licenses/MIT.

---

## 🤝 Contributing

Pull requests, issues, and feature ideas are welcome.

If you’re adding a new protocol or module:

* Keep it modular
* Document assumptions clearly
* Avoid hardcoded targets

---

## 🧪 Ethics & Responsibility

ICS systems control real-world processes. Always:

* Test only in labs or authorized environments
* Avoid actions that could cause physical damage
* Follow responsible disclosure practices

Stay safe, hack responsibly ⚙️
