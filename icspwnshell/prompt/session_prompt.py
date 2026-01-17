import ipaddress
import os, subprocess
import sys, time
import threading
from typing import TYPE_CHECKING
from icspwnshell.prompt.commands.completer import CommandCompleter
from icspwnshell.prompt.commands.nested_commands import PROTOCOLS
from icspwnshell.protocols.s7_client import S7Client
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
import optparse  # Add this import at the top of the file
import io
from contextlib import redirect_stdout, redirect_stderr
from icspwnshell.modules.modules import MODULES as modules


class SessionPrompt(CommandPrompt):
    """
    Initialize the SessionPrompt object.
        
    Returns:
        None
    """
    def __init__(self):
        self.prompt = "[  <b>➜</b>   ]"
        self.exit_flag = False
        self.target = '127.0.0.1'
        self.port = 0
        super().__init__()

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
        Retrieve the available commands.

        Returns:
            dict: A dictionary containing the available commands.
        """
        commands = {
            # Base commands always available
            'quit': {'desc': 'Exit the program'},
            'exit': {'desc': 'Exit the program'},
            'help': {'desc': 'Show all available commands', 'exec': self._cmd_help},
            'back': {'desc': 'Deselect a protocol or a module', 'exec': self._cmd_back},
            'search': {'desc': 'Search for a specific module', 'exec': self._cmd_search},
        }

        # Root level - no protocol selected
        commands['use-protocol'] = {
                'desc': 'Use a protocol (Modbus/S7comm/Opcua)', 
                'exec': self._cmd_use_protocol
            }

        # Protocol level - protocol selected but no module
        commands['use-module'] = {
                'desc': 'Select a module to use',
                'exec': self._cmd_use_module
            }
        commands['modules'] = {
                'desc': 'Show available modules',
                'exec': self._cmd_modules
            }

        commands['options'] = {
                'desc': 'Show a list of options of the module selected',
                'exec': self._cmd_show_options
            }
        commands['set'] = {
                'desc': 'Set a value to an option of the module',
                'exec': self._cmd_set
            }
        commands['run'] = {
                'desc': 'Run the selected module',
                'exec': self._cmd_run
            }
        commands['exploit'] = {
                'desc': 'Send the packet against the target',
                'exec': self._cmd_run
            }
        commands['run'] = {
                'desc': 'Send the packet against the target',
                'exec': self._cmd_run
            }

        #print(f"DEBUG: Commands generated: {list(commands.keys())}")  # Debug print
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
        toolbar_message = HTML(f'ICS PWNSHELL')

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
            print("[!] Please select a protocol to see available modules.")
            return None

        print("\n\n")
        print(f"[!] Available modules for protocol {self.protocol.upper()}:")

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
        print("\n\n")

        return None

    def _cmd_search(self, tokens):
        print("\n\n")
        print("[!] Searching for a specific module")
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
        
        if variable.lower() == 'rhost':
            if not self.is_valid_ip(value):
                self._print_error('Invalid IP address')
                return
            else:
                print(f"[!] Set RHOST to {value}\n")
                self.target = value
        if value.lower() == 'rport':
            if value < 0 or value > 65535:
                self.port = value
                print(f"[!] Set RPORT to {value}\n")

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
                print(f"[!] Set {variable} to {value} in module {self.module}\n")
                break
    # --------------------------------------------------------------- #
    def _cmd_back(self, _):
        if self.module:  # Check if a module is selected
            self.module = None
            self.options = []
            self.prompt = f"[  <b>{self.protocol.upper()}</b> ➜   ]"
            return
        if self.protocol:  # Check if a protocol is selected
            self.protocol = None
            self.prompt = "[  <b>➜</b>   ]"
            #self.refresh_commands()
            self.update_nested_completer()
            return
        self._print_error("No protocol or module to go back from.")
        

    # --------------------------------------------------------------- #

    def _cmd_show_options(self, _):
        if self.module == '' or self.module is None:
            print("\n\n")
            print("No module selected. Use the 'use' command to select a module.")
            return None
        else:
            print("\n")

            # Find the dictionary for the selected protocol
            protocol_modules = None
            for protocol_dict in modules:
                if self.protocol in protocol_dict:
                    protocol_modules = protocol_dict[self.protocol]
                    break

            if protocol_modules is None:
                self._print_error(f"No modules found for protocol {self.protocol}")
                return None

            # Find the selected module in the protocol's modules
            selected_module = None
            for module in protocol_modules:
                if module['name'] == self.module:
                    selected_module = module
                    break

            if selected_module is None:
                self._print_error(f"Module {self.module} not found in protocol {self.protocol}")
                return None

            # Print the options for the selected module with alignment
            #print(f"DEBUG Options for module {selected_module}:")
            if len(selected_module['options']) > 0:
                print(f"Options for module {self.module}:")
                print(f"{'Option Name':<20} {'Value':<15} {'Description':<50}")
                print(f"{'-' * 20} {'-' * 15} {'-' * 50}")
                print(f"{'RHOST':<20} {self.target:<15} {'Target IP address':<50}")
                print(f"{'RPORT':<20} {self.port:<15} {'Target port':<50}")

                print(f"{'-' * 20} {'-' * 15} {'-' * 50}")

                for option in selected_module['options']:
                    print(f"{option['name']:<20} {str(option.get('value', 'Not set')):<15} {option['desc']:<50}")
                print(f"{'-' * 20} {'-' * 15} {'-' * 50}")

                print("\n\n")
            else:
                print(f"[!] The module {self.module} have no options. Just run it!\n")
            return None

    # --------------------------------------------------------------- #
    #def refresh_commands(self):
        #self.commands = self.get_commands()  # Refresh the commands

    def _cmd_run(self, _):
        print("\n\n")
        print("[!] Running the module...")

        if self.module == '' or self.module is None:
            print("No module selected. Use the 'use' command to select a module.")
        
        if self.module == 'read_coils':
            #print(f"Reading {self.get_option_value('count')} coils from {self.get_option_value('target')} starting at address {self.get_option_value('start_address')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus read coils operation
            self.read_coils()
        
        if self.module == 'read_discrete_input':
            #print(f"Reading {self.get_option_value('count')} discrete inputs from {self.get_option_value('target')} starting at address {self.get_option_value('start_address')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus read discrete inputs operation
            self.read_discrete_inputs()

        if self.module == 'read_holding_registers':
            #print(f"Reading {self.get_option_value('count')} holding registers from {self.get_option_value('target')} starting at address {self.get_option_value('start_address')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus read holding registers operation
            self.read_holding_registers()

        if self.module == 'read_input_registers':
            #print(f"Reading {self.get_option_value('count')} input registers from {self.get_option_value('target')} starting at address {self.get_option_value('start_address')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus read input registers operation
            self.read_input_registers()

        if self.module == 'write_single_coil':
            #print(f"Writing single coil to {self.get_option_value('target')} at address {self.get_option_value('address')} with value {self.get_option_value('values')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus write single coil operation
            self.write_single_coil()

        if self.module == 'write_single_register':
            #print(f"Writing single holding register to {self.get_option_value('target')} at address {self.get_option_value('address')} with value {self.get_option_value('values')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the Modbus write single holding register operation
            self.write_single_register()

        if self.module == 'search_profinet':
            print("[!] Searching for Profinet devices...")
            # Here you would add the actual code to perform the Profinet search operation
            self.search_profinet()
        
        if self.module == 'info_device':
            print(f"Getting S7comm device info from {self.get_option_value('target')} on port {self.get_option_value('port')}")
            # Here you would add the actual code to perform the S7comm info device operation
            self.client_s7_connection()

        return None
    # --------------------------------------------------------------- #
    def _cmd_use_protocol(self, tokens):
        print("\n\n")
        if len(tokens) == 0:
            self._print_error('Usage: use-protocol [PROTOCOL]')
            return

        selected = tokens[0].lower()
        # Check if the selected token matches a protocol
        if selected in ['modbus', 'profinet', 's7comm']:
            self.prompt = f"[  <b>{selected.upper()}</b> ➜   ]"
            self.protocol = selected
            if selected == 'modbus':
                self.port = 502
            if selected == 's7comm':
                self.port = 102
            if selected == 'profinet':
                self.port = 34964
            self.module = None
            self.options = []
            #self.commands = self.get_commands()
            #self.refresh_commands()
            self.update_nested_completer()

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
            protocol_modules = next((protocol_dict[self.protocol] for protocol_dict in modules if self.protocol in protocol_dict), [])
            module_names = [module['name'] for module in protocol_modules]
            if selected in module_names:
                self.module = selected
                self.options = next(module['options'] for module in protocol_modules if module['name'] == selected)
                self.prompt = f"[  <b>{self.protocol.upper()}</b> ➜  <b>{selected}</b>  ]"
                self.update_nested_completer()  # Update the nested completer
                return

        # If no match is found, print an error
        self._print_error(f'Module not found in the selected protocol {self.protocol} or protocol not selected')
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
            "\n ICS Pwnshell - Tool to interact with industrial devices\n"+
            "   -  set VARIABLE VALUE             Set a value to a varible.\n"+
            "   -  use-protocol | module          Use a protocol (S7comm/Modbus/Opcua) or use module from protocol.\n"+
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
        print_formatted_text(HTML('<b>ICS pwnshell</b>:'))
    def update_nested_completer(self):
        """
        Dynamically update the NestedCompleter based on the current protocol and module.
        """
        # Start with ALL current commands (this is the key!)
        nested_commands = {}
        
        # Add all base commands first
        for cmd_name in self.commands.keys():
            nested_commands[cmd_name] = None  # Default to no subcommands
        
        # Now add protocol-specific nested commands
        if self.protocol:
            # Find the modules for the selected protocol
            protocol_modules = next((protocol_dict[self.protocol] for protocol_dict in modules 
                                    if self.protocol in protocol_dict), [])
            module_names = [module['name'] for module in protocol_modules]
            nested_commands['use-module'] = {name: None for name in module_names}
        if not self.protocol:
            nested_commands['use-protocol'] = {p: None for p in sorted(PROTOCOLS)}
        # Add module-specific options
        if self.module:
            # Find the options for the selected module
            module_options = next((module['options'] for protocol_dict in modules 
                                if self.protocol in protocol_dict
                                for module in protocol_dict[self.protocol] 
                                if module['name'] == self.module), [])
            option_names = [option['name'] for option in module_options]
            nested_commands['set'] = {name: None for name in option_names}
            nested_commands['set']['RHOST'] = None
            nested_commands['set']['RPORT'] = None


            
        
        # Update the completer with the COMPLETE command set
        self.update_nested_commands(nested_commands, self.protocol)
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
    def parse_start_address(self, value):
        addr = int(value, 16) if isinstance(value, str) and value.lower().startswith("0x") else int(value)
        if addr < 0 or addr > 0xFFFF:
            raise ValueError("start_address out of Modbus range")
        return addr

    def read_coils(self):
        """
        Function to read coils from a Modbus device.
        
        Returns:
            None
        """
        print("[+] Reading coils from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        if options is None:
            raise ValueError(
                f"No module 'read_coils' found for protocol '{self.protocol}'"
            )
        count_value = next(o["value"] for o in options if o["name"] == "COUNT")
        start_address_value = next(o["value"] for o in options if o["name"] == "START_ADDRESS")
        start_address_value = self.parse_start_address(start_address_value)
        if start_address_value < 0 or start_address_value > 0xFFFF:
            self._print_error("START_ADDRESS out of Modbus range (0-65535)")
            return
        
        if count_value < 1 or count_value > 125:
            self._print_error("COUNT out of Modbus range (1-125)")
            return
        data = mb_cl.read_coils( count_value, start_address_value)
        coils = self.decode_coils(data, count_value)
        print(f"[+] {self.target}:{self.port} - {count_value} coil values from address {start_address_value} :")
        print(f"[+] {self.target}:{self.port} - {coils}")
        print(f"[*] Read coils status operation completed.\n")

    def decode_data(self, coils_bytes, count):
        coils = []
        for byte in coils_bytes:
            for bit in range(8):
                coils.append((byte >> bit) & 0x01)
                if len(coils) == count:
                    return coils
        return coils
    def read_discrete_inputs(self):
        print("Reading discrete inputs from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        if options is None:
            raise ValueError(
                f"No module 'read_coils' found for protocol '{self.protocol}'"
            )
        count_value = next(o["value"] for o in options if o["name"] == "COUNT")
        start_address_value = next(o["value"] for o in options if o["name"] == "START_ADDRESS")
        if start_address_value < 0 or start_address_value > 0xFFFF:
            self._print_error("START_ADDRESS out of Modbus range (0-65535)")
            return
        
        if count_value < 1 or count_value > 125:
            self._print_error("COUNT out of Modbus range (1-125)")
            return
        data = mb_cl.read_discrete_input(self.target, self.port, count_value, start_address_value, timeout=5)
        decoded_inputs = self.decode_data(data, count_value)
        print(f"[+] {self.target}:{self.port} - {count_value} discrete input values from address {start_address_value} :")
        print(f"[+] {self.target}:{self.port} - {decoded_inputs}")
        print(f"[*] Read discrete inputs operation completed.\n")

    def read_holding_registers(self):
        print("Reading holding registers from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        if options is None:
            raise ValueError(
                f"No module 'read_coils' found for protocol '{self.protocol}'"
            )
        count_value = next(o["value"] for o in options if o["name"] == "COUNT")
        start_address_value = next(o["value"] for o in options if o["name"] == "START_ADDRESS")
        if start_address_value < 0 or start_address_value > 0xFFFF:
            self._print_error("START_ADDRESS out of Modbus range (0-65535)")
            return
        
        if count_value < 1 or count_value > 125:
            self._print_error("COUNT out of Modbus range (1-125)")
            return
        data = mb_cl.read_holding_register(self.target, self.port, count_value, start_address_value, timeout=5)
        data_decoded = self.decode_data(data, count_value)
        print(f"[+] {self.target}:{self.port} - {count_value} holding register values from address {start_address_value} :")
        print(f"[+] {self.target}:{self.port} - {data_decoded}")
        print(f"[*] Read holding registers operation completed.\n")

    def read_input_registers(self):
        print("Reading input registers from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        if options is None:
            raise ValueError(
                f"No module 'read_coils' found for protocol '{self.protocol}'"
            )
        count_value = next(o["value"] for o in options if o["name"] == "COUNT")
        start_address_value = next(o["value"] for o in options if o["name"] == "START_ADDRESS")

        if start_address_value < 0 or start_address_value > 0xFFFF:
            self._print_error("START_ADDRESS out of Modbus range (0-65535)")
            return
        
        if count_value < 1 or count_value > 125:
            self._print_error("COUNT out of Modbus range (1-125)")
            return

        data = mb_cl.read_input_registers(self.target, self.port, count_value, start_address_value, timeout=5)

        data_decoded = self.decode_data(data, count_value)
        print(f"[+] {self.target}:{self.port} - {count_value} input register values from address {start_address_value} :")
        print(f"[+] {self.target}:{self.port} - {data_decoded}")
        print(f"[*] Read input registers operation completed.\n")


    def write_single_register(self):
        print("Writing single register to Modbus device...")
        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        if options is None:
            raise ValueError(
                f"No module 'read_coils' found for protocol '{self.protocol}'"
            )
        address_value = next(o["value"] for o in options if o["name"] == "ADDRESS")
        value_value = next(o["value"] for o in options if o["name"] == "VALUE")
        
        if address_value < 0 or address_value > 0xFFFF:
            self._print_error("ADDRESS out of Modbus range (0-65535)")
            return
        if value_value < 0 or value_value > 0xFFFF:
            self._print_error("VALUE out of Modbus range (0-65535)")
            return

        mb_cl = Modbus(self.target, self.port)
        mb_cl.write_single_register(self.target, self.port, address_value, value_value)

    def write_single_coil(self):
        print("Writing coil to Modbus device...")
        options = next(
            (
                module["options"]
                for protocol_dict in modules
                if self.protocol in protocol_dict
                for module in protocol_dict[self.protocol]
                if module.get("name") == self.module
            ),
            None
        )

        if options is None:
            raise ValueError(
                f"No module 'read_coils' found for protocol '{self.protocol}'"
            )
        address_value = next(o["value"] for o in options if o["name"] == "ADDRESS")
        value_value = next(o["value"] for o in options if o["name"] == "VALUE")
        
        if int(value_value) != 0 or int(value_value) != 1:
            print(f"{value_value}")
            self._print_error("[!] VALUE must be 0 (OFF) or 1 (ON)")
            return
        
        if address_value < 0 or address_value > 0xFFFF:
            self._print_error("ADDRESS out of Modbus range (0-65535)")
            return

        mb_cl = Modbus(self.target, self.port)
        mb_cl.write_single_coil(self.target, self.port, address_value, value_value)
    
    def write_multiple_registers(self):
        print("Writing multiple registers to Modbus device...")
        print("Writing coil to Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.write_multiple_registers(self.target, self.port, address_value, value_value)
    
    def write_multiple_coils(self):
        print("Writing multiple coils to Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.write_multiple_coils()
    

    

    def masked_write_register(self):
        print("Performing masked write register on Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.mask_write_register()

    def read_write_multiple_registers(self):
        print("Performing read/write multiple registers on Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.read_write_multiple_registers()

    def read_fifo_queue(self):
        print("Reading FIFO queue from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.read_fifo_queue()

    def read_multiple_registers(self):
        print("Reading multiple registers from Modbus device...")
        
        mb_cl = Modbus(self.target, self.port)
        mb_cl.read_multiple_registers()

    def client_s7_connection(self):
        print("Establishing S7comm client connection...")
        return None

    def search_profinet(self):
        
        profinet_cl = Profinet()
        src_mac = profinet_cl.get_src_mac()

        # Use optparse directly instead of referencing it as an attribute of profinet_cl
        #parser = optparse.OptionParser()
        #parser.add_option('-i', dest="src_iface", 
        #                default="", help="source network interface")
        #options, args = parser.parse_args()
        
        #src_iface = options.src_iface or profinet_cl.get_src_iface()
        src_iface = profinet_cl.get_src_iface()
        
        # Run sniffer
        t = threading.Thread(target=profinet_cl.sniff_packets, args=(src_iface,))
        t.setDaemon(True)
        t.start()

        # Create and send broadcast Profinet packet
        payload = 'fefe 05 00 04010002 0080 0004 ffff '
        payload = payload.replace(' ', '')
        buf = io.StringIO()

        pp = Ether(type=0x8892, src=src_mac, dst=profinet_cl.cfg_dst_mac) / bytes.fromhex(payload)
        print("[>] Sending Profinet discovery packet...")
        with redirect_stdout(buf), redirect_stderr(buf):
            ans, unans = srp(pp)

        print("\n[<] Profinet discovery packets sent.\n")
        for line in buf.getvalue().splitlines():
            line = line.strip()

            if not line or line in {"^C"}:
                continue

            else:
                print(f"[!] {line}")
        # Wait for sniffer to finish
        t.join()

        # Parse and print result
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

        print("[!] Found %d devices" % len(result))
        print("[!] {0:17} : {1:15} : {2:15} : {3:9} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}".format(
            'MAC Address', 
            'Type of Station', 
            'Name of Station', 
            'Vendor ID', 
            'Device ID', 
            'Device Role', 
            'IP Address', 
            'Subnet Mask', 
            'Standard Gateway'
        ))
        for (mac, profinet_info) in result.items():
            p = result[mac]
            print("[!] {0:17} : {1:15} : {2:15} : {3:9} : {4:9} : {5:11} : {6:15} : {7:15} : {8:15}".format(
                mac, 
                p['type_of_station'], 
                p['name_of_station'], 
                p['vendor_id'],
                p['device_id'],
                p['device_role'],
                p['ip_address'],
                p['subnet_mask'],
                p['standard_gateway']
            ))
        return None
    # --------------------------------------------------------------- #
    def flashing_led(self):
        #### To Test ####
        s7_cl = S7Client()
        print("Flashing LED on S7comm device...")
        interfaces = s7_cl.getAllInterfaces()
        #mac_address = s7_cl.get_if_hwaddr('eth6')
        mac_address = ''
        npfdevice = None
        macaddr = None
        winguid = None
        for i in interfaces:
            if i[2] == mac_address:
                npfdevice = i[0]
                macaddr = i[2].replace(':', '') # eg: 'ab58e0ff585a'
                winguid = i[4]

        if not npfdevice:
            return

        if os.name == 'nt': 
            npfdevice = r'\\Device\\NPF_' + winguid


        dmac = s7_cl.getMac("192.168.1.14", "eth6")
        device={}
        device['name_of_station'] = ''
        device['mac_address'] = dmac
        s7_cl.flashLED(npfdevice, device, macaddr, 3)
        return None
    
    # ================================================================#
    def s7_info_device(self):
        #### To Test ####
        s7_cl = S7Client()
        print("Getting info from S7comm device...")
        #s7_cl.get_device_info(self.target, self.port)
        return None