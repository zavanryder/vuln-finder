"""Safe: Command execution -- no shell, args as list."""
import subprocess

def ping_host(host):
    result = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True)
    return result.stdout

def list_dir(path):
    import os
    entries = os.listdir(path)
    return entries
