import os
import time
from .prompt.session_prompt import SessionPrompt
from prompt_toolkit import HTML, print_formatted_text

# Define the octopus arm ASCII art
arm = [r"""
 _____ _____  _____ 
|_   _/  __ \/  ___|  
  | | | /  \/\ `--.    
  | | | |     `--. \      
 _| |_| \__/\/\__/ /      
 \___/ \____/\____/                                                   
______ _    _ _   _  _____ _   _  _____ _      _     
| ___ \ |  | | \ | |/  ___| | | ||  ___| |    | |    
| |_/ / |  | |  \| |\ `--.| |_| || |__ | |    | |    
|  __/| |/\| | . ` | `--. \  _  ||  __|| |    | |    
| |   \  /\  / |\  |/\__/ / | | || |___| |____| |____
\_|    \/  \/\_| \_/\____/\_| |_/\____/\_____/\_____/

By @stuxve
"""]

    


# Define a function to print the arm movement
def print_arm_movement(arm):
    for i in range(len(arm)):
        print(arm[i])
        time.sleep(0.1)  # Add a small delay between prints to create the illusion of movement
def print_intros(num):
    for i in range(num):
        print("\n")


def main():
    print_intros(4)
    print_arm_movement(arm)
    time.sleep(1.5)

    session = SessionPrompt()
    print("\nWrite 'help' to get all the info commands availables\n")
    print_formatted_text(HTML('Welcome to the <b>ICS Pwnshell</b>'))

    session.start_prompt()


if __name__ == "__main__":
    main()