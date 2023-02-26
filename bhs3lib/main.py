#!/usr/bin/python3

from .ansicolor import *
import argparse
import sys
import yaml
import os
import winrm

DATA_FOLDER = r"./attack_tests/"


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        allow_abbrev=False,
        description="BHSecurity3 script to simulate adversary using MITRE ATT&CK framework",
    )
    parser.add_argument("target", action="store", help="IP address to attack e.g. 192.168.1.10", nargs="?")
    parser.add_argument("atomic_test", action="store", help="Atomic test to run e.g. T1083", nargs="?")
    parser.add_argument("-u", action="store", help="Target host username", default="", required=False)
    parser.add_argument("-p", action="store", help="Target host password", default="", required=False)
    parser.add_argument("-l", action="store_true", help="List atomic tests available")
    parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')
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

    
    hostname = arglist['target']
    if hostname == None:
        print(bad(red("Hostname argument required")))
        parser.print_help()
        sys.exit()
    test = arglist['atomic_test']
    if test == None:
        print(bad(red("Atomic test argument required")))
        parser.print_help()
        sys.exit()
    username = arglist['u']
    password = arglist['p']

    filename = DATA_FOLDER + test + ".yaml"
    data = load_data(filename)
    atomic_tests=[]
    for x in data['cmd'].splitlines():
        if x:
            atomic_tests.append(x.strip())
    exec=data['execution']
    remote_test(hostname, username, password, exec, atomic_tests)
    pass

def load_data(file) -> dict:
    with open(file, 'r', encoding="utf-8") as f:
        return yaml.safe_load(f.read())
    
def remote_test(ip, username, password, execution, commands):
    print(good("Connecting to {} ...".format(ip)))
    s = winrm.Session(ip, auth=(username, password))
    print(good("Connected"))
    if execution == "cmd":
        for cmd in commands:
            print(good("Executing command: {}".format(cmd))) 
            r = s.run_cmd(cmd)
            if r.status_code != 0:
                print(bad("Command execution error"))
                continue
            print(good("Done!"))
            if r.std_out != '':
                line = r.std_out.decode('utf-8')
                print(good(u"{}\n".format(line)))
            # if r.std_err != '':    
            #     print(bad(r.std_err))
    if execution == "powershell":
        for cmd in commands:
            print(good("Executing command: {}".format(cmd))) 
            r = s.run_ps(cmd)
            if r.status_code != 0:
                print(bad("Command execution error"))
                continue
            print(good("Done!"))
            if r.std_out != '':
                line = r.std_out.decode('utf-8')
                print(good(u"{}\n".format(line)))
            # if r.std_err != '':    
            #     print(bad(r.std_err))


if __name__ == "__main__":
    main()
