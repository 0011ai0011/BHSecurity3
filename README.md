# BHS3-test

This python script is used to execute MITRE - ATT&ACK Atomic Red Team tests on windows environment to test detection and defensive capabilities against techniques defined within Atomic Red Team.

Atomic Red Team™(1) is a library of simple tests that every security team can execute to test their controls. Tests are focused, have few dependencies, and are defined in a structured format that can be used by automation frameworks.

MITRE ATT&CK is a curated knowledge base and model for cyber adversary behavior, reflecting the various phases of an adversary’s attack lifecycle and the platforms they are known to target (2)

## Installation

Copy the entire directory in your folder and run the script.

### Prerequisites

The following libraries are required and must installed:

- pyyaml
- pywinrm

## Usage

From a bash shell:

python3 bhs3-test.py [-u U] [-p P] [-l] [-h] [target] [atomic_test]

positional arguments:
  target       IP address to attack e.g. 192.168.1.10
  atomic_test  Atomic test to run e.g. T1083

options:
  -u U         Target host username
  -p P         Target host password
  -l           List atomic tests available
  -h, --help   Show this help message and exit.

Example:

python3 bhs3-test.py 172.16.233.147 T1082-P2 -u john -p 12345678

Using -l options only, the script shows all the tests available. For example

python3 bhs3-test.py -l 
BHSecurity3 script to simulate adversary using MITRE ATT&CK framework
 
Atomic tests available: 
 
[+] T1082-P2 - System Information Discovery with WMIC (powershell)
[+] T1083-P - File and Directory Discovery (powershell)
[+] T1083-C - File and Directory Discovery (cmd)
[+] T1059.003-C - Command and Scripting Interpreter Windows Command Shell (cmd)
[+] T1082-C - System Information Discovery (cmd)
[+] T1082-P - System Information Discovery (powershell)

## Author

* Antonio Imperi (https://github.com/pongs74)

## License

Copyright 2023 - BHSecurity3

## Shoutout

- Thanks to Norihda, Patricia and Atul for sharing valuable knowledge and support.

## References

(1) - https://atomicredteam.io/
(2) - https://attack.mitre.org/docs/ATTACK_Design_and_Philosophy_March_2020.pdf
