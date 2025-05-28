import sys
import subprocess

if sys.platform.startswith("win"):

    commands = [
        ".\\tui\\target\\release\\tui"
    ]

elif sys.platform.startswith(["linux", "darwin"]):

    commands = [
        "chmod u+x ./tui/target/release/tui",
        "./tui/target/release/tui"
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

