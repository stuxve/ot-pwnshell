MODULES = [
    {
        'modbus': [
            {'name': 'modbus_read_coils', 'desc': 'Modbus Read Coils Fuzzer', "options": [
                {'name': 'count', 'desc': 'Number of coils to read', "mandatory":True, "value": 10},
                {'name': 'start_address', 'desc': 'Starting address to read from', "mandatory":True, "value": 0}
            ]},
            {'name': 'modbus_write_single_coil', 'desc': 'Modbus Write Single Coil Fuzzer', "options": [
                {'name': 'address', 'desc': 'Address to write to', "mandatory":True, "value": 0},
                {'name': 'value', 'desc': 'Value to write (0 or 1)', "mandatory":True, "value": 1}
            ]}
        ]
    },
    {
        's7comm': [
            {'name': 'info_device', 'desc': 'S7comm Info Device Module', "options": []}
        ]
    },
    {
        'profinet': [
            {'name': 'search_profinet', 'desc': 'Search for Profinet Devices', "options": []}
        ]
    }
    
]