import os
import time
from .prompt.session_prompt import SessionPrompt
from prompt_toolkit import HTML, print_formatted_text
import random
from .constants import arm1, arm2, arm3, arm4, arm5

arm_ar = [arm1, arm2, arm3, arm4, arm5]

arm = random.choice(arm_ar)
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
    print_intros(2)
    time.sleep(1.5)
    print_intros(20)

    session = SessionPrompt()
    print("\nWrite 'help' to get all the info commands availables\n")
    print_formatted_text(HTML('Welcome to the <b>ICS Pwnshell</b>'))
    session.start_prompt()


if __name__ == "__main__":
    main()