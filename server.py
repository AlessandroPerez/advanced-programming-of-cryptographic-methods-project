import sys
import subprocess

if sys.platform.startswith("win"):

    commands = [
        ".\\target\\release\\updater.exe",
        ".\\target\\release\\server.exe",
    ]

elif sys.platform.startswith(["linux", "darwin"]):

    commands = [
        "chmod u+x ./target/release/updater",
        "chmod u+x ./target/release/server",
        "./target/release/updater",
        "./target/release/server",
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

