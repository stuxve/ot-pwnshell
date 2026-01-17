PROTOCOLS = ["modbus", "s7comm", "profinet"]


NESTED_COMMANDS = {
    "use-protocol": {p: None for p in sorted(PROTOCOLS)}
}