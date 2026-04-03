"""Vulnerable: OS command injection via subprocess with shell=True."""
import subprocess

def ping_host(host):
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return result.stdout

def list_dir(path):
    import os
    os.system("ls -la " + path)
