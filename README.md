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

* [ ] Read Coils (Modbus)
* [ ] Write Coils (Modbus)
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

## ☕ Support the Project

If you find **ICS PWNSHELL** useful and want to support ongoing research and development, you can buy me a coffee:

👉 **Buy Me a Coffee**: [https://buymeacoffee.com/stuxve](https://buymeacoffee.com/stuxve)

Every coffee helps keep the research going ❤️

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
