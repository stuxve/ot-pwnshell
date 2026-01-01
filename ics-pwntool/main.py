import os
import time
from .prompt.session_prompt import SessionPrompt
from prompt_toolkit import HTML, print_formatted_text

# Define the octopus arm ASCII art
arm = [ 
" ## ##   #### ##  \n"
"##   ##  # ## ##  \n"
"##   ##    ##     \n"
"##   ##    ##     \n"
"##   ##    ##     \n"
"##   ##    ##     \n"
" ## ##    ####    \n"
"                  \n"
"### ##   ##   ##  ###  ##   ## ##   ###  ##  ### ###  ####     ####     \n"
" ##  ##  ##   ##    ## ##  ##   ##   ##  ##   ##  ##   ##       ##      \n"
" ##  ##  ##   ##   # ## #  ####      ##  ##   ##       ##       ##      \n"
" ##  ##  ## # ##   ## ##    #####    ## ###   ## ##    ##       ##      \n"
" ## ##   # ### #   ##  ##      ###   ##  ##   ##       ##       ##      \n"
" ##       ## ##    ##  ##  ##   ##   ##  ##   ##  ##   ##  ##   ##  ##  \n"
"####     ##   ##  ###  ##   ## ##   ###  ##  ### ###  ### ###  ### ###  \n"
"\nBy @stuxve              \n"
]
    


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


    # Mostrar menú de selección para ejecutar o detener un fuzzer
    #filename = "logs/octopus.log" # Replace with the name of the file you want to create
    # If file exists, delete it
    #os.chdir(f'{os.path.dirname(__file__)}')

    #if os.path.isfile(filename):
    #    os.remove(filename)
    #os.chdir(f'../')
    session = SessionPrompt()
    print("\nWrite 'help' to get all the info commands availables\n")
    print_formatted_text(HTML('Welcome to the <b>OT Pwnshell</b>'))

    session.start_prompt()


if __name__ == "__main__":
    main()