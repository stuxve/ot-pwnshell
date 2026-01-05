import os
import signal
import threading
from prompt_toolkit.styles import Style
from prompt_toolkit import PromptSession, HTML, print_formatted_text
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
import sys

from .helpers import get_tokens
from .commands import CommandHandler, CommandCompleter, COMMANDS, NESTED_COMMANDS
from prompt_toolkit.completion import NestedCompleter, merge_completers, DynamicCompleter
from prompt_toolkit.history import FileHistory
from icspwnshell.modules.modules import MODULES as modules

class CommandPrompt(object):
    def __init__(self) -> None:
        """
        Constructor of the CommandPrompt class.
        
        Attributes:
            commands (dict): A dictionary containing the available commands.
            nested_commands (dict): A dictionary containing the available nested commands.
            cmd_handler (CommandHandler): Command handler.
            completer (Completer): Command completer.
            style (Style): Style for the command line interface.
            _break (bool): Flag to indicate if the program should exit.
            auto_suggest (AutoSuggestFromHistory): Auto suggestions based on command history.
            prompt_session (PromptSession): Session for the command line interface.
            lock (Lock): Lock to ensure safe access to shared resources.
            history (FileHistory): Command history stored in a file.
        """
        self.protocol = None
        self.module = None
        self.commands = self.get_commands()
        self.nested_commands = self.get_nested_commands()
        self.cmd_handler = CommandHandler(self.commands)
        self.completer = merge_completers([CommandCompleter(self.commands), NestedCompleter.from_nested_dict(self.nested_commands)], deduplicate = True)
        #self.completer = DynamicCompleter(self._get_completer)
        self.style = self.get_style()
        self._break = False
        self.auto_suggest = AutoSuggestFromHistory()
        self.prompt_session = PromptSession(completer=self.completer, style=self.style,
                                            bottom_toolbar=self.bottom_toolbar,
                                            auto_suggest=self.auto_suggest)
        super(CommandPrompt, self).__init__()
        self.lock = threading.Lock()
        self.history = FileHistory('.octopus_command_history')

    # --------------------------------------------------------------- #
    def _get_completer(self):
        return NestedCompleter.from_nested_dict(self._build_nested_commands())
    
    def _build_nested_commands(self):
        nested = {
            'use-protocol': {p: None for p in ['modbus', 'profinet', 's7comm']},
        }

        if self.protocol:
            protocol_modules = next(
                (d[self.protocol] for d in modules if self.protocol in d),
                []
            )
            #nested['use-module'] = {
            #    m['name']: None for m in protocol_modules
            #}

        if self.module:
            module_options = next(
                (m['options']
                for d in modules if self.protocol in d
                for m in d[self.protocol]
                if m['name'] == self.module),
                []
            )
            nested['set'] = {
                o['name']: None for o in module_options
            }

        return nested
    def get_commands(self):
        """
        Retrieve the available commands.
        
        Returns:
            dict: A dictionary containing the available commands.
        """
        return COMMANDS
    
    def get_nested_commands(self):
        """
        Retrieve the available nested commands.
        
        Returns:
            dict: A dictionary containing the available nested commands.
        """
        return NESTED_COMMANDS
    
    def update_nested_commands(self, commands):
        """
        Update the commands with the given commands dictionary.
        
        Args:
            commands (dict): A dictionary containing the commands to be added.
        """
        # REPLACE instead of UPDATE - this is the critical fix!
        self.nested_commands = commands.copy()  # Or just: self.nested_commands = commands
        
        #self.commands = self.get_commands()
        self.completer = merge_completers([
            CommandCompleter(self.commands), 
            NestedCompleter.from_nested_dict(self.nested_commands)
        ], deduplicate=True)
        self.prompt_session.completer = self.completer

    def set_completer(self, completer):
        """
        Set the command completer for the prompt session.
        
        Args:
            completer (Completer): The command completer to be set.
        """
        self.prompt_session.completer = completer
    # --------------------------------------------------------------- #

    def get_prompt(self):
        """
        Get the prompt text.
        
        Returns:
            HTML: The prompt text as an HTML object.
        """
        return HTML('[<b>>   ➜  </b>]$')

    # --------------------------------------------------------------- #

    def get_style(self):
        """
        Get the style for the prompt.
        
        Returns:
            None
        """
        Style.from_dict({
            'completion-menu.completion': 'bg:#008888 #ffffff',
            'completion-menu.completion.current': 'bg:#00aaaa #000000',
            'scrollbar.background': 'bg:#88aaaa',
            'scrollbar.button': 'bg:#222222',
            'token.literal.string.single': '#98ff75'
        })

    # --------------------------------------------------------------- #

    def intro_message(self):
        """
        Print an introduction message when starting the prompt.
        
        Returns:
            None
        """
        print_formatted_text(HTML('<b>Starting prompt...</b>'))
    # --------------------------------------------------------------- #

    def exit_message(self):
        """
        Print an exit message when exiting the prompt.
        
        Returns:
            None
        """
        print_formatted_text(HTML('<b>Exiting prompt...</b>'))

    # --------------------------------------------------------------- #

    def handle_exit(self, tokens: list) -> None:
        """
        Handle the 'exit', 'quit', or 'q' command to exit the prompt.
        
        Args:
            tokens (list): A list of tokens representing the command input.
        
        Returns:
            None
        """
        if len(tokens) > 0:
            if tokens[0] in ('exit', 'quit', 'q'):
                try:
                    sys.exit(0)
                except:
                    print(sys.exc_info()[0])


    # --------------------------------------------------------------- #

    def handle_break(self, tokens: list) -> bool:
        """
        Handle the 'c' or 'continue' command to determine whether to continue the prompt or not.
        
        Args:
            tokens (list): A list of tokens representing the command input.
        
        Returns:
            bool: True if the command is 'c' or 'continue', False otherwise.
        """
        if tokens[0] in ('c', 'continue'):
            return True
        else:
            return False
    # --------------------------------------------------------------- #

    def handle_command(self, tokens: list) -> None:
        """
        Handle a command entered in the prompt.
        
        Args:
            tokens (list): A list of tokens representing the command input.
        
        Returns:
            None
        """
        if len(tokens) > 0:
            self.cmd_handler.handle_command(tokens)

    # --------------------------------------------------------------- #

    def bottom_toolbar(self):
        """
        Return the bottom toolbar for the prompt.
    
        Returns:
            None
        """
        return None

    
    # --------------------------------------------------------------- #

    def start_prompt(self) -> None:
        """
        Start the prompt and handle user input until exit command is entered.
    
        Returns:
            None
        """
        while True:
            try:
                self.intro_message()
                cmd = self.prompt_session.prompt(
                    self.get_prompt,
                    completer=self.completer
                )
                tokens = get_tokens(cmd)

                if not self.handle_break(tokens):
                    self.handle_exit(tokens)
                    self.handle_command(tokens)

            except KeyboardInterrupt:
                continue
            except EOFError:
                break
        self.exit_message()