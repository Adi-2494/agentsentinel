import subprocess


def main():
    branch = input("branch: ")
    subprocess.call("git checkout " + branch, shell=True)  # SINK command
