MODULES = [
    {
        'modbus': [
            {'name': 'read_coils', 'desc': 'Modbus Read Coils ', "options": [
                {'name': 'COUNT', 'desc': 'Number of coils to read', "mandatory":True, "value": 10},
                {'name': 'START_ADDRESS', 'desc': 'Starting address to read from', "mandatory":True, "value": 0}
            ]},
            {'name': 'read_input_status', 'desc': 'Modbus Read Discrete Inputs ', "options": [
                {'name': 'COUNT', 'desc': 'Number of discrete inputs to read', "mandatory":True, "value": 10},
                {'name': 'START_ADDRESS', 'desc': 'Starting address to read from', "mandatory":True, "value": 0}
            ]},
            {'name': 'read_holding_registers', 'desc': 'Modbus Read Holding Registers ', "options": [
                {'name': 'COUNT', 'desc': 'Number of holding registers to read', "mandatory":True, "value": 10},
                {'name': 'START_ADDRESS', 'desc': 'Starting address to read from', "mandatory":True, "value": 0}
            ]},
            {'name': 'read_input_registers', 'desc': 'Modbus Read Input Registers ', "options": [
                {'name': 'COUNT', 'desc': 'Number of input registers to read', "mandatory":True, "value": 10},
                {'name': 'START_ADDRESS', 'desc': 'Starting address to read from', "mandatory":True, "value": 0}
            ]},
            {'name': 'write_single_coil', 'desc': 'Modbus Write Single Coil ', "options": [
                {'name': 'ADDRESS', 'desc': 'Address to write to', "mandatory":True, "value": 0},
                {'name': 'VALUES', 'desc': 'Value to write (0 or 1)', "mandatory":True, "value": 1}
            ]},
            {'name': 'write_single_register', 'desc': 'Modbus Write Single Holding Register ', "options": [
                {'name': 'ADDRESS', 'desc': 'Address to write to', "mandatory":True, "value": 0},
                {'name': 'VALUES', 'desc': 'Value to write (0-65535)', "mandatory":True, "value": 0}
            ]},
            {'name': 'write_multiple_coils', 'desc': 'Modbus Write Multiple Coils ', "options": [
                {'name': 'START_ADDRESS', 'desc': 'Starting address to write to', "mandatory":True, "value": 0},
                {'name': 'VALUES', 'desc': 'List of values to write (0 or 1)', "mandatory":True, "value": [1,0,1,0,1]}
            ]},
            {'name': 'write_multiple_registers', 'desc': 'Modbus Write Multiple Holding Registers ', "options": [
                    {'name': 'START_ADDRESS', 'desc': 'Starting address to write to', "mandatory":True, "value": 0},
                    {'name': 'VALUES', 'desc': 'List of values to write (0-65535)', "mandatory":True, "value": [100,200,300]}
            ]}
        ]
        
    },

    {
        's7comm': [
            {'name': 'info_device', 'desc': 'S7comm Info Device Module', "options": []},
            {'name': 'flash_led', 'desc': 'S7comm Blink LED Module', "options": []}
        ]
    },
    {
        'profinet': [
            {'name': 'search_profinet', 'desc': 'Search for Profinet Devices', "options": []},
            {'name': 'blink_led', 'desc': 'S7comm Blink LED Module', "options": []}

        ]
    }
    

]