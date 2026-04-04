# Linux Firewall Manager (Python + UFW)

This project is a simple firewall management tool written in Python.  
It automates common UFW firewall commands on Linux systems and provides a small command-line interface to manage firewall rules.

The goal of this project was to practice Linux security basics, firewall configuration, and Python automation.

## Features

- Enable or disable the firewall
- Allow specific TCP ports
- Deny specific TCP ports
- Block IP addresses
- Allow IP addresses
- Reset firewall rules
- Show current firewall status
- Input validation for ports and IP addresses
- Basic logging of firewall actions

## Technologies Used

- Python
- Linux
- UFW (Uncomplicated Firewall)
- subprocess module

## How It Works

The script acts as a simple CLI tool.  
Instead of manually running UFW commands in the terminal, the program allows the user to manage firewall rules through a menu.

Example operations include:

- enabling the firewall
- opening or closing ports
- blocking suspicious IP addresses
- resetting firewall rules

The program also validates user input to avoid invalid ports or IP addresses.

## Example Usage

Run the script:

python3 firewall_manager.py

Then choose an option from the menu:

1 Enable Firewall  
2 Disable Firewall  
3 Allow Port  
4 Deny Port  
5 Show Status  
6 Block IP  
7 Allow IP  
8 Reset Firewall  
9 Exit
<img width="655" height="943" alt="Screenshot 2026-04-04 230738" src="https://github.com/user-attachments/assets/52295456-df50-4a8b-be72-4f68bf55b837" />

## Learning Outcome

This project helped reinforce several core concepts:

- basic firewall management on Linux
- understanding network ports and access control
- automating system commands with Python
- building simple CLI tools
- validating user input for security
