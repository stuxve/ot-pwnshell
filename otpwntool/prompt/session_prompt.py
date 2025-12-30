import ipaddress
import os, subprocess
import sys, time
import threading
from typing import TYPE_CHECKING
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles
from prompt_toolkit.shortcuts import prompt
import re
#from Octopus.prompt.helpers import get_tokens


from .prompt import CommandPrompt
#from Octopus import constants
#from Octopus.fuzzer import Fuzzer
from ..constants import *
from otpwntool.prompt.helpers import get_tokens
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory


modules = [
    'modbus', [
        {'name': 'modbus_read_coils', 'desc': 'Modbus Read Coils Fuzzer', "options": [
            {'name': 'target', 'desc': 'Target IP address'},
            {'name': 'port', 'desc': 'Target Port'},
            {'name': 'count', 'desc': 'Number of coils to read'},
            {'name': 'start_address', 'desc': 'Starting address to read from'}
        ]},
        {'name': 'modbus_write_single_coil', 'desc': 'Modbus Write Single Coil Fuzzer', "options": [
            {'name': 'target', 'desc': 'Target IP address'},
            {'name': 'port', 'desc': 'Target Port'},
            {'name': 'address', 'desc': 'Address to write to'},
            {'name': 'value', 'desc': 'Value to write (0 or 1)'}
        ]},
    ]
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
                'desc': 'Show a list of fuzzing sessions',
                'exec': self._cmd_show_options
            },
            'modules': {
                'desc': 'Show a list of modules sessions',
                'exec': self._cmd_show_options
            },
            'search': {
                'desc': 'Search for a specific module',
                'exec': self._cmd_search
            },
            'exploit': {
                'desc': 'Send the packet against the target',
                'exec': self._cmd_run
            },
            'use': {
                'desc': 'Show logs uf the current fuzzing session',
                'exec': self._cmd_use
            },
            'help': {
                'desc': 'Show all available commands',
                'exec': self._cmd_help
            },
            'back': {
                'desc': 'Kill a session',
                'exec': self._cmd_back
            },
            'set': {
                'desc': 'Create a fuzzing session',
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
        print("\n\n")
        print("Showing available modules")
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
        
    def _cmd_back(self, _):

        self.prompt = "[  <b>➜</b>   ]"
        self.protocol = ''

    # --------------------------------------------------------------- #

    def _cmd_show_options(self, _):
        print(
            "\n Options for the action:\n"+
            f"   -  target {self.target}               See sessions opened or fuzzing modules loaded fuzzers.\n"+
            f"   -  port {self.port}                   See sessions opened or fuzzing modules loaded sessions.\n"
            f"   -  action {self.action}                 (0 - Read Coil / 1 - Start / 2 - Stop)\n"
        ) 
        print("\n\n")
        return None

    # --------------------------------------------------------------- #

    def _cmd_run(self, _):
        print("\n\n")
        print("Running the action")
        return None
    # --------------------------------------------------------------- #

    def _cmd_use(self, tokens):
        print("\n\n")
        if tokens[0].lower() == 'modbus':
            self.prompt = "[  <b>MODBUS</b> ➜   ]"
            self.protocol = 'modbus'
        if tokens[0].lower() == 'opcua':
            self.prompt = "[  <b>OPC UA</b>   ]"
            self.protocol = 'opcua'
        if tokens[0].lower() == 's7comm':
            self.prompt = "[  <b>S7COMM</b> ]"
            self.protocol = 's7comm'
        
        
        if self.protocol != 'modbus' and self.protocol != 'opcua' and self.protocol != 's7comm':
                self._print_error('Protocol not selected')
                return
        return None

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