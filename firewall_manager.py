import subprocess
from datetime import datetime
import ipaddress

LOG_FILE = "firewall.log"

def log_action(action):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {action}\n")

def run_command(command):
    subprocess.run(command)

def valid_port(port):
    if port.isdigit():
        port = int(port)
        if 1 <= port <= 65535:
            return True
    return False

def valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def enable_firewall():
    run_command(["sudo","ufw","enable"])
    log_action("Firewall enabled")

def disable_firewall():
    run_command(["sudo","ufw","disable"])
    log_action("Firewall disabled")

def allow_port(port):
    run_command(["sudo","ufw","allow",f"{port}/tcp"])
    log_action(f"Allowed port {port}/tcp")

def deny_port(port):
    run_command(["sudo","ufw","deny",f"{port}/tcp"])
    log_action(f"Denied port {port}/tcp")

def block_ip(ip):
    run_command(["sudo","ufw","deny","from",ip])
    log_action(f"Blocked IP {ip}")

def allow_ip(ip):
    run_command(["sudo","ufw","allow","from",ip])
    log_action(f"Allowed IP {ip}")

def reset_firewall():
    run_command(["sudo","ufw","reset"])
    log_action("Firewall reset")

def show_status():
    run_command(["sudo","ufw","status","numbered"])

while True:

    print("""
=== FIREWALL MANAGER ===

1 Enable Firewall
2 Disable Firewall
3 Allow Port
4 Deny Port
5 Show Status
6 Block IP
7 Allow IP
8 Reset Firewall
9 Exit

""")

    choice = input("Select: ")

    if choice == "1":
        enable_firewall()

    elif choice == "2":
        disable_firewall()

    elif choice == "3":
        port = input("Port: ")

        if valid_port(port):
            allow_port(port)
        else:
            print("Invalid port")

    elif choice == "4":
        port = input("Port: ")

        if valid_port(port):
            deny_port(port)
        else:
            print("Invalid port")

    elif choice == "5":
        show_status()

    elif choice == "6":
        ip = input("IP to block: ")

        if valid_ip(ip):
            block_ip(ip)
        else:
            print("Invalid IP")

    elif choice == "7":
        ip = input("IP to allow: ")

        if valid_ip(ip):
            allow_ip(ip)
        else:
            print("Invalid IP")

    elif choice == "8":
        reset_firewall()

    elif choice == "9":
        break
