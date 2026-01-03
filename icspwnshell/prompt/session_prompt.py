import ipaddress
import os, subprocess
import sys, time
import threading
from typing import TYPE_CHECKING
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles
from prompt_toolkit.shortcuts import prompt
import re

from icspwnshell.protocols.modbus import Modbus
from icspwnshell.protocols.profinet import Profinet
#from Octopus.prompt.helpers import get_tokens

from scapy.all import conf, sniff, srp, Ether
from .prompt import CommandPrompt
#from Octopus import constants
#from Octopus.fuzzer import Fuzzer
from ..constants import *
from icspwnshell.prompt.helpers import get_tokens
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory


modules = [
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
    }
    
]

class SessionPrompt(CommandPrompt):
    """
    Initialize the SessionPrompt object.
        
    Returns:
        None
    """
    def __init__(self):
        super().__init__()
        self.prompt = "[  <b>➜</b>   ]"
        self.exit_flag = False
        self.module = ''
        self.protocol = ''
        self.target = ''
        self.port = 0

    # ================================================================#
    # CommandPrompt Overridden Functions                              #
    # ================================================================#

    def get_nested_commands(self):
        """
        Get the nested commands by calling the parent class's get_nested_commands() method and updating it with an empty dictionary.
        
        Returns:
            dict: The nested commands dictionary.
        """
        nested_commands = super().get_nested_commands()
        nested_commands.update({})
        return nested_commands
    
    def get_commands(self):
        """
        Get the full list of commands.
        
        Returns:
            dict: The commands dictionary.
        """

        """ Contains the full list of commands"""
        commands = super().get_commands()
        commands.update({
            'options': {
                'desc': 'Show a list of options of the module selected',
                'exec': self._cmd_show_options
            },
            'search': {
                'desc': 'Search for a specific module',
                'exec': self._cmd_search
            },
            'modules': {
                'desc': 'Show available modules',
                'exec': self._cmd_modules
            },
            'exploit': {
                'desc': 'Send the packet against the target',
                'exec': self._cmd_run
            },
            "use-protocol": {
                'desc': 'Use a protocol (Modbus/S7comm/Opcua)',
                'exec': self._cmd_use_protocol
            },
            "use-module": {
                'desc': 'Use a protocol (Modbus/S7comm/Opcua)',
                'exec': self._cmd_use_module
            },
            'help': {
                'desc': 'Show all available commands',
                'exec': self._cmd_help
            },
            'back': {
                'desc': 'Deselect a protocol or a module',
                'exec': self._cmd_back
            },
            'set': {
                'desc': 'Set a value to an option of the module',
                'exec': self._cmd_set
            },
        })
        

        return commands

    # --------------------------------------------------------------- #

    def get_prompt(self):
        """
        Get the prompt text.
        
        Returns:
            HTML: The prompt text as an HTML object.
        """
        return HTML(f'{self.prompt}  $ ')

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        """
        Create the bottom toolbar message.
        
        Returns:
            HTML: The toolbar message as an HTML object.
        """
        toolbar_message = HTML(f'OT PWNSHELL')

        return toolbar_message


    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        """
        Handle the exit command.
        
        Args:
            tokens (list): A list of command tokens.
        
        Returns:
            None
        """
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                #Change flag to stop all Threads
                self.exit_flag = True
                self.exit_message()
                sys.exit(0)



    # --------------------------------------------------------------- #

    def _print_color(self, color, message):
        """
        Print a colored message.
        
        Args:
            color (str): The color of the message.
            message (str): The message to be printed.
        
        Returns:
            None
        """
        print_formatted_text(HTML(f'<{color}>{message}</{color}>'),
                             style=self.get_style())

    # --------------------------------------------------------------- #

    def _print_error(self, message):
        """
        Print an error message.
        
        Args:
            message (str): The error message to be printed.
        
        Returns:
            None
        """
        self._print_color('red', message)

    # ================================================================#
    # Command handlers                                                #
    # ================================================================#
    def is_valid_ip(self, ip_address):
        """
        Check if an IP address is valid.
        
        Args:
            ip_address (str): The IP address to be validated.
        
        Returns:
            bool: True if the IP address is valid, False otherwise.
        """
        # Regular expression pattern for matching an IP address
        pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        
        if not re.match(pattern, ip_address):
            return False
        
        # Split the IP address into its components
        components = ip_address.split('.')
        
        # Check that each component is between 0 and 255
        for component in components:
            if int(component) < 0 or int(component) > 255:
                return False
        
        return True
    # --------------------------------------------------------------- #
    def _cmd_modules(self, tokens):
        if not self.protocol:
            print("\n\n")
            print("Please select a protocol to see available modules.")
            return None

        print("\n\n")
        print(f"Available modules for protocol {self.protocol.upper()}:")

        # Find the dictionary for the selected protocol
        protocol_modules = None
        for protocol_dict in modules:
            if self.protocol in protocol_dict:
                protocol_modules = protocol_dict[self.protocol]
                break

        if protocol_modules is None:
            self._print_error(f"No modules found for protocol {self.protocol}")
            return None

        # Print the available modules for the selected protocol
        for mod in protocol_modules:
            print(f" - {mod['name']}: {mod['desc']}")
        return None

    def _cmd_search(self, tokens):
        print("\n\n")
        print("Searching for a specific module")
        return None

    def _cmd_set(self, tokens):
        """
        Set the value of a variable.
        
        Args:
            tokens (list): A list of command tokens.
        
        Returns:
            None
        """
        
        if len(tokens) < 2:
            self._print_error('Usage: set [OPTION] [VALUE]')
            return

        variable = ''.join(tokens[0])
        value = ' '.join(tokens[1:])
        
        if variable.lower() == 'target':
            if not self.is_valid_ip(value):
                self._print_error('Invalid IP address')
                return
            else:
                self.target = value
        if tokens.lower() == 'port':
            if value < 0 or value > 65535:
                self.port = value

        # Check if a module is selected
        if self.module == '':
            self._print_error('No module selected. Use the "use" command to select a module.')
            return
        # Find the option in the selected module
        option_found = False
        for option in self.options:
            if option['name'].lower() == variable.lower():
                option['value'] = value
                option_found = True
                print(f"Set {variable} to {value} in module {self.module}")
                break


    # --------------------------------------------------------------- #
    def _cmd_back(self, _):
        if self.module:  # Check if a module is selected
            self.module = ''
            self.options = []
            self.prompt = f"[  <b>{self.protocol.upper()}</b> ➜   ]"
            return
        if self.protocol:  # Check if a protocol is selected
            self.protocol = ''
            self.prompt = "[  <b>➜</b>   ]"
            return
        self._print_error("No protocol or module to go back from.")
        

    # --------------------------------------------------------------- #

    def _cmd_show_options(self, _):
        if self.module == '':
            print("\n\n")
            print("No module selected. Use the 'use' command to select a module.")
            return None
        else:
            print("\n\n")
            print("Target options:")
            print(f" - LHOST: {self.target}")
            print(f" - LPORT: {self.port}\n")
            if len(modules[self.protocol][self.module]['options']) > 0:
                print(f"Options for module {self.module}:")
                for option in self.options:
                    print(f" - {option['name']}: {option['value']}")
        return None

    # --------------------------------------------------------------- #

    def _cmd_run(self, _):
        print("\n\n")
        print("Running the module...")

        if self.module == '':
            print("No module selected. Use the 'use' command to select a module.")
        
        if self.module == 'modbus_read_coils':
            print(f"Reading {self.get_option_value('count')} coils from {self.get_option_value('target')} starting at address {self.get_option_value('start_address')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus read coils operation


        return None
    # --------------------------------------------------------------- #
    def _cmd_use_protocol(self, tokens):
        print("\n\n")
        if len(tokens) == 0:
            self._print_error('Usage: use-protocol [PROTOCOL]')
            return

        selected = tokens[0].lower()

        # Check if the selected token matches a protocol
        if selected in ['modbus', 'opcua', 's7comm']:
            self.prompt = f"[  <b>{selected.upper()}</b> ➜   ]"
            self.protocol = selected
            self.module = ''
            self.options = []
            return

        # If no match is found, print an error
        self._print_error('Protocol not found')
        return
    def _cmd_use_module(self, tokens):
        print("\n\n")
        if len(tokens) == 0:
            self._print_error('Usage: use-module [MODULE]')
            return

        selected = tokens[0].lower()

        # Check if the selected token matches a module within the current protocol
        if self.protocol:
            protocol_modules = None
            for protocol_dict in modules:
                if self.protocol in protocol_dict:
                    protocol_modules = protocol_dict[self.protocol]
                    break

            if protocol_modules:
                module_names = [module['name'] for module in protocol_modules]
                if selected in module_names:
                    self.module = selected
                    self.options = next(module['options'] for module in protocol_modules if module['name'] == selected)
                    self.prompt = f"[  <b>{self.protocol.upper()}</b> ➜  <b>{selected}</b>  ]"
                    return

        # If no match is found, print an error
        self._print_error(f'Module not found in the selected protocol {self.protocol} or protocol not selected')
        return
    
    def _cmd_use(self, tokens):
        print("\n\n")
        if len(tokens) == 0:
            self._print_error('Usage: use [PROTOCOL | MODULE]')
            return

        selected = tokens[0].lower()

        # Check if the selected token matches a protocol
        if selected in ['modbus', 'opcua', 's7comm']:
            self.prompt = f"[  <b>{selected.upper()}</b> ➜   ]"
            self.protocol = selected
            self.module = ''
            self.options = []
            return

        # Check if the selected token matches a module within the current protocol
        if self.protocol:
            protocol_modules = None
            for protocol_dict in modules:
                if self.protocol in protocol_dict:
                    protocol_modules = protocol_dict[self.protocol]
                    break

            if protocol_modules:
                module_names = [module['name'] for module in protocol_modules]
                if selected in module_names:
                    self.module = selected
                    self.options = next(module['options'] for module in protocol_modules if module['name'] == selected)
                    self.prompt = f"[  <b>{self.protocol.upper()}</b> ➜  <b>{selected}</b>  ]"
                    return

        # If no match is found, print an error
        self._print_error('Module not found in the selected protocol or protocol not selected')
        return

    # --------------------------------------------------------------- #

    def _cmd_help(self, _):
        """
        Display the help message.
        
        Args:
            _ (str): Unused argument.
        
        Returns:
            None
        """
        print(
            "\n OT Pwnshell - Tool to interact with ICS devices\n"+
            "   -  set VARIABLE VALUE             Set a value to a varible.\n"+
            "   -  use PROTOCOL | MODULE          Use a protocol (S7comm/Modbus/Opcua) or use module from protocol.\n"+
            "   -  modules                        Show available modules.\n"+
            "   -  protocols                      Show available protocols.\n"+
            "   -  exploit                        Send the action against the target.\n"+
            "   -  search PROTOCOL | MODULE       Search for a specific module or modules from a protocol.\n"+
            "   -  show-options                   Show variables of the action to send.\n"+
            "   -  back                           Back when using a protocol.\n"+
            "   -  exit                           Exit the shell.\n"
        ) 
 

    # --------------------------------------------------------------- #

    def get_files_and_folders(self, path):
        """
        Get files and folders in a given path.
        
        Args:
            path (str): The path to scan.
        
        Returns:
            dict: A dictionary containing files and folders in the path.
        """
        result = {}
        for entry in os.scandir(path):
            if entry.is_file():
                result[entry.name] = None
            elif entry.is_dir():
                result[entry.name] = self.get_files_and_folders(entry.path)
        return result


    def get_style(self):
        """
        Get the style for the prompt.
        
        Returns:
            PromptStyle: The merged style for the prompt.
        """
        return merge_styles([super().get_style(), Style.from_dict(STYLE)])

    # --------------------------------------------------------------- #
    def intro_message(self):
        """
        Print the intro message when the prompt starts.
        
        Returns:
            None
        """
        print_formatted_text(HTML('<b>OT pwnshell</b>:'))

    # --------------------------------------------------------------- #

    def exit_message(self):
        """
        Print the exit message when the prompt ends.
        
        Returns:
            None
        """
        print("\n")
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))
        

    # --------------------------------------------------------------- #
    # Functions of the modules                                        #
    # --------------------------------------------------------------- #

    def modbus_read_coils(self):
        """
        Function to read coils from a Modbus device.
        
        Returns:
            None
        """
        print("Reading coils from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.read_coils()
    

    def client_s7_connection(self):
        print("Establishing S7comm client connection...")
        return None

    def search_profinet(self):
        
        print("Searching for Profinet devices...")
        profinet_cl = Profinet()
        src_mac = profinet_cl.get_src_mac()
        parser = profinet_cl.optparse.OptionParser()
        parser.add_option('-i', dest="src_iface", 
                        default="", help="source network interface")
        options, args = parser.parse_args()
        
        src_iface = options.src_iface or profinet_cl.get_src_iface()
        
        # run sniffer
        t = threading.Thread(target=profinet_cl.sniff_packets, args=(src_iface,))
        t.setDaemon(True)
        t.start()

        # create and send broadcast profinet packet
        payload =  'fefe 05 00 04010002 0080 0004 ffff '
        payload = payload.replace(' ', '')

        pp = Ether(type=0x8892, src=src_mac, dst=profinet_cl.cfg_dst_mac)/payload.decode('hex')
        ans, unans = srp(pp)

        # wait sniffer...
        t.join()

        # parse and print result
        result = {}
        for p in profinet_cl.sniffed_packets:
            if hex(p.type) == '0x8892' and p.src != src_mac:
                result[p.src] = {'load': p.load}
                type_of_station, name_of_station, vendor_id, device_id, device_role, ip_address, subnet_mask, standard_gateway = profinet_cl.parse_load(p.load, p.src)
                result[p.src]['type_of_station'] = type_of_station
                result[p.src]['name_of_station'] = name_of_station
                result[p.src]['vendor_id'] = vendor_id
                result[p.src]['device_id'] = device_id
                result[p.src]['device_role'] = device_role
                result[p.src]['ip_address'] = ip_address
                result[p.src]['subnet_mask'] = subnet_mask
                result[p.src]['standard_gateway'] = standard_gateway

        print("found %d devices" % len(result))
        print("{0:17} : {1:15} : {2:15} : {3:9} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}").format('mac address', 'type of station', 
                                                                                                'name of station', 'vendor id', 
                                                                                                'device id', 'device role', 'ip address',
                                                                                                'subnet mask', 'standard gateway')
        for (mac, profinet_info) in result.items():
            p = result[mac]
            print("{0:17} : {1:15} : {2:15} : {3:9} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}").format(mac, 
                                                                                                    p['type_of_station'], 
                                                                                                    p['name_of_station'], 
                                                                                                    p['vendor_id'],
                                                                                                    p['device_id'],
                                                                                                    p['device_role'],
                                                                                                    p['ip_address'],
                                                                                                    p['subnet_mask'],
                                                                                                    p['standard_gateway'],
                                                                                                    )

        return None