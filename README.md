Honeypy

A simple honeypot project that emulates both SSH and HTTP login portals to capture and log unauthorized access attempts.
Features

    SSH Honeypot: Emulates an SSH server, logs login attempts and commands.
    HTTP Honeypot: Presents a fake WordPress admin login page, logs login attempts.
    Rotating Logs: All events are logged with rotation for audit purposes.

Requirements

    Python 3.12+
    pip

Installation

Clone the repository:

git clone <your-repo-url>
cd Honeypy

Install required Python libraries:

    Flask (for the web honeypot)
    Paramiko (for the SSH honeypot)

Install both with:

pip install flask paramiko

    All other libraries (argparse, logging, threading, socket) are part of the Python standard library and do not require installation.

Generate SSH server key (for SSH honeypot):

ssh-keygen -t rsa -f server.key

    Place server.key in the project root.

Usage
SSH Honeypot

Run the SSH honeypot with:

python honeypy.py -s -a <address> -p <port> -u <username> -pw <password>

Example:

python honeypy.py -s -a 0.0.0.0 -p 2223 -u admin -pw password

HTTP Honeypot

Run the HTTP honeypot with:

python honeypy.py -w -a <address> -p <port> -u <username> -pw <password>

Example:

python honeypy.py -w -a 0.0.0.0 -p 5000 -u admin -pw password

The web honeypot will be available at http://<address>:<port>/.
File Structure

    honeypy.py: Main entry point, argument parsing.
    ssh_honeypot.py: SSH honeypot implementation.
    web_honeypot.py: HTTP honeypot implementation.
    templates/wp-admin.html: Fake WordPress login page.
    server.key: SSH server private key (required for SSH honeypot).
    Log files: audits.log, cmd_audits.log, http_audits.log (rotated).

Documentation

    Flask Documentation
    Paramiko Documentation
    Python Logging
