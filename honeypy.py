# Libraries
import argparse
from ssh_honeypot import *
from web_honeypot import *

# Parse Arguments

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSH Honeypot")
    parser.add_argument('-a', '--address', type=str, required=True)
    parser.add_argument('-p', '--port', type=int, required=True)
    parser.add_argument('-u', '--username', type=str )
    parser.add_argument('-pw', '--password', type=str)

    
    parser.add_argument('-s', '--ssh', action="store_true")
    parser.add_argument('-w', '--http', action="store_true")

    args = parser.parse_args()

try:
    if args.ssh:
        print("[-] Running SSH Honeypot...")
        honeypot(args.address, args.port, args.username, args.password)

    elif args.http:
        print("[-] Running HTTP Honeypot...")

        if not args.username:
            args.username = "admin"
        if not args.password:
            args.password = "password"

        print(f"Port: {args.port} Username: {args.username} Password: {args.password}")
        run_web_honeypot(args.port, args.username, args.password)

        run_web_honeypot(port=5000, input_username="admin", input_password="password")

        pass
    else:
        print("[!] You can only choose SSH (-s) (-ssh) or HTTP (-h) (-http) when running script.")

except:
    print("\n Exiting HoneyPY...\n")
        