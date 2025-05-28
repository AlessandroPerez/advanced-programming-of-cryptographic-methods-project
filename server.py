import sys
import subprocess

if sys.platform.startswith("win"):

    commands = [
        ".\\config\\update_server_keys\\target\\release\\update_server_keys.exe",
        ".\\server\\target\\release\\server.exe"
    ]

elif sys.platform.startswith(["linux", "darwin"]):

    commands = [
        "chmod u+x ./config/update_server_keys/target/release/update_server_keys",
        "chmod u+x ./server/target/release/server",
        "./config/update_server_keys/target/release/update_server_keys",
        "./server/target/release/server"
    ]

else:
    raise Exception("Not supported")

for command in commands:

    try:
        process = subprocess.Popen(command, shell=True)
        process.wait()

        assert process.returncode == 0, f"'{command}' failed with return code: {process.returncode}"
    
    except Exception as e:
        print(f"An error occurred while executing '{command}': {e}")

