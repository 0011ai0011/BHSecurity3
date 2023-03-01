#!/usr/bin/python3

"""
bhs-test.py - Python script used to execute MITRE - ATT&ACK tests on windows environment.

version: 1.0
author: Antonio Imperi @ BHSecurity3

Copyright 2023 - BHSecurity3
"""


# import libraries
from .ansicolor import *
import argparse
import sys
import yaml
import os
import winrm

# tests scripts data folder
DATA_FOLDER = r"./attack_tests/"


# main function executed everytime the script is launched
def main():
    # *******************************************************************
    # This scripts section parse the command line arguments and store them
    # in predefined variables
    # *******************************************************************
    parser = argparse.ArgumentParser(
        add_help=False,
        allow_abbrev=False,
        description="BHSecurity3 script to simulate adversary using MITRE ATT&CK framework",
    )
    parser.add_argument(
        "target",
        action="store",
        help="IP address to attack e.g. 192.168.1.10",
        nargs="?",
    )
    parser.add_argument(
        "atomic_test", action="store", help="Atomic test to run e.g. T1083", nargs="?"
    )
    parser.add_argument(
        "-u", action="store", help="Target host username", default="", required=False
    )
    parser.add_argument(
        "-p", action="store", help="Target host password", default="", required=False
    )
    parser.add_argument("-l", action="store_true", help="List atomic tests available")
    parser.add_argument(
        "-h",
        "--help",
        action="help",
        default=argparse.SUPPRESS,
        help="Show this help message and exit.",
    )
    args, unknown = parser.parse_known_args()
    arglist = vars(args)
    if arglist["l"]:
        print(parser.description)
        print(" ")
        print("Atomic tests available: ")
        print(" ")
        for file in os.listdir(DATA_FOLDER):
            if file.endswith(".yaml"):
                filename = DATA_FOLDER + file
                with open(filename) as f:
                    data = yaml.load(f, Loader=yaml.FullLoader)
                    print(good("{} - {}".format(data["test"], data["name"])))
        sys.exit()
    hostname = arglist["target"]
    if hostname == None:
        print(bad(red("Hostname argument required")))
        parser.print_help()
        sys.exit()
    test = arglist["atomic_test"]
    if test == None:
        print(bad(red("Atomic test argument required")))
        parser.print_help()
        sys.exit()
    username = arglist["u"]
    password = arglist["p"]
    # *************************************************************************

    # create the filename of the script
    filename = DATA_FOLDER + test + ".yaml"

    # load MITRE ATT&ACK script in selected in the command line
    data = load_data(filename)

    # array that will contains the scripts
    atomic_tests = []
    for x in data["cmd"].splitlines():
        if x:
            atomic_tests.append(x.strip())
    exec = data["execution"]

    # execute the remote test
    remote_test(hostname, username, password, exec, atomic_tests)  #
    pass


def load_data(file) -> dict:
    """
    Load YAML (human-readable data-serialization language) script
    from yaml files located in the DATA_FOLDER directory

    :param file: file path name of the YAML file
    :return: dictionary style formatted data of the file content
    """
    with open(file, "r", encoding="utf-8") as f:
        return yaml.safe_load(f.read())


def remote_test(ip, username, password, execution, commands):
    """
    Execute powershell or command line script using WinRM Windows
    Remote Management service client.

    :param ip: remote host ip address (e.g. 192.168.0.1)
    :param username: username to access remote host
    :param password: password to access remote host
    :param execution: cmd or powershell
    :param commands: command to execute (oneliner)
    """
    print(good("Connecting to {} ...".format(ip)))
    
    # open the session with the remote host
    s = winrm.Session(ip, auth=(username, password))
    print(good("Connected"))
    
    # if the commands are to run in terminal
    if execution == "cmd":
        for cmd in commands:
            print(good("Executing command: {}".format(cmd)))

            # Execute the command 
            r = s.run_cmd(cmd)

            # Check if there is an error
            if r.status_code != 0:
                print(bad("Command execution error"))
                continue
            print(good("Done!"))
            print(good("Results:"))
            if r.std_out != "":
                # convert results from bytes to strings 
                line = r.std_out.decode("utf-8")
                print(good("{}\n".format(line)))
            # if r.std_err != '':
            #     print(bad(r.std_err))

    # if the commands are to run in powershell        
    if execution == "powershell":
        for cmd in commands:
            print(good("Executing command: {}".format(cmd)))
            
            # execute the command
            r = s.run_ps(cmd)

            # Check if there is an error
            if r.status_code != 0:
                print(bad("Command execution error"))
                continue
            print(good("Done!"))
            print(good("Results:"))
            if r.std_out != "":
                # convert results from bytes to strings
                line = r.std_out.decode("utf-8")
                print(good("{}\n".format(line)))
            # if r.std_err != '':
            #     print(bad(r.std_err))


if __name__ == "__main__":
    main()
