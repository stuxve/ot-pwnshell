import ipaddress
import os, subprocess
import sys, time
import threading
from typing import TYPE_CHECKING
from prompt_toolkit import HTML, print_formatted_text
from prompt_toolkit.styles import Style, merge_styles
from prompt_toolkit.shortcuts import prompt
import re
from Octopus.prompt.helpers import get_tokens


from .prompt import CommandPrompt
from Octopus import constants
from Octopus.fuzzer import Fuzzer
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory

fuzzers_id = 0

class SessionPrompt(CommandPrompt):
    """
    Initialize the SessionPrompt object.
        
    Returns:
        None
    """
    def __init__(self):
        super().__init__()
        self.fuzzers = []
        self.active_fuzzers = []
        self.prompt = "[  <b>➜</b>   ]"
        self._cmd_load("")
        self.exit_flag = False

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
            'load': {
                'desc': 'Load fuzzing modules in folder \'fuzzers\'',
                'exec': self._cmd_load
            },
            'show-fuzzers': {
                'desc': 'Show a list of fuzzers loaded',
                'exec': self._cmd_show_fuzzers
            },
            'show-sessions': {
                'desc': 'Show a list of fuzzing sessions',
                'exec': self._cmd_show_sessions
            },
            'show-logs': {
                'desc': 'Show logs uf the current fuzzing session',
                'exec': self._cmd_show_logs
            },
            'help': {
                'desc': 'Show all available commands',
                'exec': self._cmd_help
            },
            'kill': {
                'desc': 'Kill a session',
                'exec': self._cmd_kill
            },
            'create': {
                'desc': 'Create a fuzzing session',
                'exec': self._cmd_create_fuzzer
            },
            'scan-ports': {
                'desc': 'Scan ports of a target',
                'exec': self._cmd_scan_ports
            }

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
        toolbar_message = HTML(f'Fuzzer Orquestator')

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
                for t in self.active_fuzzers:
                    #Change flag to stop all Threads
                    t.kill_thread = True
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

    def _cmd_scan_ports_error(self, valid):
        """
        Handle an error message in the scan-ports command.
        
        Args:
            valid (bool): True if the error is due to the command usage, False if it is due to an invalid target IP.
        
        Returns:
            None
        """
        if valid:
            self._print_error(f'<red>[!] Error in scan-ports command\nscan-ports usage: scan-ports  [TARGET-IP]. \nExample:\n'
                                  f'\t$ scan-ports 127.0.0.1\n</red>')
        else:
            self._print_error(f'<red>[!] Target IP is not valid\n'
                                   f'scan-ports usage: scan-ports [TARGET-IP]. \nExample:\n'
                                  f'\t$ scan-ports 127.0.0.1\n</red>')
    # --------------------------------------------------------------- #
    def _cmd_scan_ports(self, tokens):
        """
        Execute the scan-ports command to scan for open ports on a target IP address.
        
        Args:
            tokens (list): The command tokens containing the target IP address.
        
        Returns:
            None
        """
        ch = tokens
        if len(ch) < 1:
            self._cmd_scan_ports_error(True)
            return
        if not self.is_valid_ip(ch[0]):
            self._cmd_scan_ports_error(False)
            return
        # Define the nmap command to run
        nmap_command_tcp = f"sudo nmap -p20000,44818,1089-1091,102,502,4840,80,443,34962-34964,4000 {ch[0]} --disable-arp-ping"
        nmap_command_udp = f"sudo nmap -sU -p47808,20000,34980,2222,44818,55000-55003,1089-1091,34962-34964,4000,55555,45678,1541,11001,5450,50020-50021,5050-5051,9600,1089,1090,1541,1541,2222,4000,5050-5051,9600,11001,20000,34962,34963,34964,34980,44818,45678,47808,50020-50021,55000-55002,55003,55555 {ch[0]} --disable-arp-ping"

        # Execute the nmap command and capture the output
        nmap_process_tcp = subprocess.Popen(nmap_command_tcp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)
        nmap_process_udp = subprocess.Popen(nmap_command_udp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, shell=True)

        # Wait for the nmap command to finish executing
        nmap_output_tcp, nmap_error_tcp = nmap_process_tcp.communicate()
        nmap_output_udp, nmap_error_udp = nmap_process_udp.communicate()

        # Check if there was an error running nmap
        if nmap_process_udp.returncode != 0 or nmap_process_tcp.returncode != 0:
            print(f"Error running nmap tcp: {nmap_error_tcp}")
            print(f"Error running nmap udp: {nmap_error_udp}")
        else:
            # Parse the nmap output to find open ports
            open_ports = []
            for line in nmap_output_tcp.split("\n"):
                if("0 hosts up") in line:
                    print("Target is not up for tcp scan.")
                    return
                if ("open" in line or "filtered" in line) and "/tcp" in line:
                    port = line.split("/")[0]
                    open_ports.append(["tcp", port])
            for line in nmap_output_udp.split("\n"):
                if("0 hosts up") in line:
                    print("Target is not up for tcp scan.")
                    return
                if ("open" in line or "filtered" in line) and "/udp" in line:
                    port = line.split("/")[0]
                    open_ports.append(["udp", port])
            if len(open_ports) == 0:
                print("No open ports found on arget.")
                return
            print("[!] TCP Ports to scan: 20000,44818,1089-1091,102,502,4840,80,443,34962-34964,4000 \n")
            print("[!] TCP Scan output:\n")
            print(nmap_output_tcp)
            print("[!] UDP Ports to scan: 47808,20000,34980,2222,44818,55000-55003,1089-1091,34962-34964,4000,55555,45678,1541,11001,5450,50020-50021,5050-5051,9600,1089,1090,1541,1541,2222,4000,5050-5051,9600,11001,20000,34962,34963,34964,34980,44818,45678,47808,50020-50021,55000-55002,55003,55555 \n")
            print("[!] UDP Scan output:\n")
            print(nmap_output_udp)
            print("\n")
            for prot, port in open_ports:
                for fuzzer in self.fuzzers:
                    if int(port) == 502 and fuzzer[0] == 'boofuzz-modbus':
                        print_formatted_text(HTML(f'\n<green>[!] Recommendation</green> ➜  Fuzzer: {fuzzer[0]} could be used with modbus on target. Open port 502 {prot}\n'))
                    if int(port) == 102 and fuzzer[0] == '61850-fuzzing':
                        print_formatted_text(HTML(f'\n<green>[!] Recommendation</green>  ➜ Fuzzer: {fuzzer[0]} could be used with 61850 MMS on target. Open port 102 {prot}.\n'))
    # --------------------------------------------------------------- #

    def _cmd_kill_error(self):
        """
        Print an error message for the kill command if the command format is invalid.
        
        Returns:
            None
        """
        self._print_error(f'<red>[!] Error in kill command\n kill usage: kill [FUZZER-ID]. \n'
                            f'\tFirst check the id of the session to kill with \'show-sessions\'  :\n'
                            f'\tExample:\n'
                            f'\t$ kill 0\n</red>')
    # --------------------------------------------------------------- #

    def _cmd_kill(self, tokens):
        """
        Execute the kill command to stop and remove a fuzzing session.
        
        Args:
            tokens (list): The command tokens containing the fuzzer ID.
        
        Returns:
            None
        """
        ch = tokens
        if len(ch) < 1 or not isinstance(ch[0], int):
            self._cmd_kill_error()
            return
        id = int(ch[0])
        isFuzzer = False
        index = None
        counter = 0
        kill_fuzzer = None
        for fuzzer in self.active_fuzzers:
            if id == fuzzer.id:
                isFuzzer = True
                index = counter
                kill_fuzzer = fuzzer
            counter += 1

        if isFuzzer:
            kill_fuzzer.stop()
            self.fuzzers.pop(index)
            self.active_fuzzers.pop(index)
            print("Fuzzer "+str(index)+" removed correctly.")
        else:
            self._cmd_kill_error()
            return

    # --------------------------------------------------------------- #

    def _cmd_load(self, _):
        """
        Load fuzzing modules in Octopus and update the nested commands.
        
        Args:
            _ (str): Unused argument.
        
        Returns:
            None
        """
        print("\nLoading fuzzing modules in Octopus...")
        loadedModules = []
        completer = {
            "create":{
            
            }
        }
        path = os.path.dirname(__file__)+"/../fuzzers"
        subdirectories = [directory for directory in os.listdir(path) if os.path.isdir(os.path.join(path, directory))]
        for fuzzer_load in subdirectories:
            isLoaded = False
            for fuzzer in self.fuzzers:
                if fuzzer_load in fuzzer[0] or fuzzer_load in fuzzer[1]:
                    isLoaded = True        
            if isLoaded == False:
                self.fuzzers.append([fuzzer_load, "fuzzers/"+fuzzer_load])
                loadedModules.append(fuzzer_load)
                completer["create"][fuzzer_load] = None
        nested_commands = super().get_nested_commands()
        nested_commands.update(completer)
        super().update_nested_commands(nested_commands)
        nested_commands2 = super().get_nested_commands()

        if len(loadedModules) > 0:
            print("\nThe fuzzing modules loaded are:\n")
            for fuzzer_name in loadedModules:
                print(f"    -    {fuzzer_name}\n")
        elif len(loadedModules) == 0:
            print("No se han cargado modulos de fuzzing.")
        


    # --------------------------------------------------------------- #

    def _cmd_show_fuzzers(self, tokens):
        """
        Display the loaded fuzzers.
        
        Args:
            tokens (list): The command tokens.
        
        Returns:
            None
        """
        print("\n\n")
        print("Fuzzers loaded:\n")

        for row in self.fuzzers:
            print("| {:<20} | {:<30} |".format(row[0], row[1]))

        print("\n")

    # --------------------------------------------------------------- #
       
    def _cmd_show_logs(self, tokens):
        """
        Display the contents of the octopus.log file.
        
        Args:
            tokens (list): The command tokens.
        
        Returns:
            None
        """
        filename = "octopus.log"
        os.chdir(f'{os.path.dirname(__file__)+"/.."}')

        self.lock.acquire()
        # Replace with the name of the file you want to create
        with open(filename, "r") as f:
            lines = f.readlines()[-20:]
            for line in lines:
                print(line.strip())
        self.lock.release()

        print(f"To see this log file go to log folder in file: {filename}")
    # --------------------------------------------------------------- #

    def _cmd_show_sessions(self, tokens):
        """
        Show a list of fuzzer sessions.
        
        Args:
            tokens (list): The command tokens.
        
        Returns:
            None
        """
        self.bottom_toolbar = "Fuzzer Orquestrator"
        start = "-   "
        for fuzzer in self.active_fuzzers:
            id = str(fuzzer.id)+"  "
            name = fuzzer.name+"     "
            if fuzzer.active:
                active = " Running      "
            else:
                active = " Stopped      "
            if fuzzer.end_time == None:
                now_time = time.time()
                timer = now_time-fuzzer.start_time
                hours = timer // 3600
                minutes = (timer // 60) % 60
                seconds = timer % 60
                time_str = f"{hours:.2f} hours {minutes:.2f} minutes {seconds:.2f} seconds"
            else: 
                timer = fuzzer.end_time-fuzzer.start_time
                hours = timer // 3600
                minutes = (timer // 60) % 60
                seconds = timer % 60
                time_str = f"{hours:.2f} hours {minutes:.2f} minutes {seconds:.2f} seconds"

            
            print("\n")
            print(start+id+name+active+time_str)
            print("\n")


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
            "\n Fuzzing Orquestrator Tool: Works with fuzzers for ICS protocols.\n"+
            "   -  show-fuzzers                    See sessions opened or fuzzing modules loaded fuzzers.\n"+
            "   -  show-sessions                   See sessions opened or fuzzing modules loaded sessions.\n"+
            "   -  load                            Load fuzzing modules.\n"+
            "   -  kill       [Fuzzer Name]        Kill a given session.\n"+
            "   -  create     [Fuzzer Name]        Create a session of a given fuzzer.\n"+
            "   -  scan-ports [target ip]          Scan open ports of a given ip target address.\n"
        )

    # --------------------------------------------------------------- #
    def _cmd_create_fuzzer_error(self):
        """
        Print an error message for the create command.
        
        Returns:
            None
        """
        self._print_error(f'<red>[!] Error in create command \ncreate usage: create [FUZZER-FOLDER-NAME]. \nExample:\n'
                                  f'\t$ create boofuzz-modbus\n'
                                  f'\t$ create 61850-fuzzing</red>')
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
    
    # --------------------------------------------------------------- #

    def _cmd_create_fuzzer(self, tokens):
        """
        Create a fuzzer session.
        
        Args:
            tokens (list): A list of command tokens.
        
        Returns:
            None
        """
        global fuzzers_id
        ch = tokens
        if len(ch) < 1 or len(self.fuzzers) == 0:
            self._cmd_create_fuzzer_error()
            return
        fuzzer_path = None
        fuzzer_name = None
        for fuzzName, fuzzPath in self.fuzzers:
            if(ch[0]==fuzzName):
                fuzzer_path = fuzzPath
                fuzzer_name = fuzzName
                break
        if fuzzer_path == None or fuzzer_name == None:
            self._cmd_create_fuzzer_error()
            return
        if fuzzer_path is None:
            self._cmd_create_fuzzer_error()
            return
        path = os.chdir(f'{os.path.dirname(__file__)+"/../"+fuzzer_path}')

        dict_commands = self.get_files_and_folders(path)
        dict_com = {
            "python3": dict_commands
        }
        completer_execution = NestedCompleter.from_nested_dict(dict_com)


        print(f"\n\nIntroduce the command to execute the fuzzer, remember that you are now in the folder {fuzzer_path}, to come back use the command \'back\'.\n")
        prompt_string = f"[{fuzzer_name} ➜ ({fuzzer_path})] $ "
        
        cmd = self.prompt_session.prompt(prompt_string, completer=completer_execution)
        tokens = get_tokens(cmd)

        if not self.handle_break(tokens):
            self.handle_exit(tokens)
        if cmd == "back":
            return
        while True:
            if cmd == "":
                print(f"\n\nIntroduce the command to execute the fuzzer, remember that you are now in the folder {fuzzer_path}, to come back use the command \'back\'.")
                prompt_string = f"[{fuzzer_name}({fuzzer_path})] $ "

                cmd = self.prompt_session.prompt(prompt_string, completer=completer_execution)
                tokens = get_tokens(cmd)

                if not self.handle_break(tokens):
                    self.handle_exit(tokens)
                elif cmd == "back":
                    return
                continue
            fuzzer_thread =  Fuzzer(fuzzer_name, fuzzer_path, cmd, self, fuzzers_id, self.lock)
            fuzzers_id += 1
            fuzzer_thread.start()
            self.active_fuzzers.append(fuzzer_thread)
            isDead = False
            for _ in range(1,10):
                if fuzzer_thread.is_alive() == False:
                    isDead = True
                    break
                time.sleep(0.01)
            
            if isDead == False:
                break
                
            os.chdir(f'../..')

            print(f"\n\nIntroduce the command to execute the fuzzer, remember that you are now in the folder {fuzzer_path}, to come back use the command \'back\'.")
            prompt_string = f"[{fuzzer_name}({fuzzer_path})] $ "

            cmd = self.prompt_session.prompt(prompt_string, completer=completer_execution)
            tokens = get_tokens(cmd)

            if not self.handle_break(tokens):
                self.handle_exit(tokens)
            elif cmd == "back":
                return
            

    # --------------------------------------------------------------- #


    def get_style(self):
        """
        Get the style for the prompt.
        
        Returns:
            PromptStyle: The merged style for the prompt.
        """
        return merge_styles([super().get_style(), Style.from_dict(constants.STYLE)])

    # --------------------------------------------------------------- #
    def intro_message(self):
        """
        Print the intro message when the prompt starts.
        
        Returns:
            None
        """
        print_formatted_text(HTML('<b>Octopus Shell</b>:'))

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