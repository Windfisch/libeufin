# Helpers for the integration tests.

from subprocess import check_call, Popen, PIPE, DEVNULL
import socket
from requests import post, get
from time import sleep
import atexit
from pathlib import Path
import sys

class CheckJsonField:
    def __init__(self, name, nested = []):
        self.name = name
        self.nested = nested

    def check(self, json):
        if self.name not in json:
            print(f"'{self.name}' not found in the JSON.")
            sys.exit(1)
        for nested_check in self.nested:
            self.nested_check.check(json.get(self.name))

class CheckJsonTop:
    def __init__(self, *args):
        self.checks = args

    def check(self, json):
        for check in self.checks:
            check.check(json)

def checkPort(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("0.0.0.0", port))
        s.close()
    except:
        print(f"Port {port} is not available")
        print(sys.exc_info()[0])
        exit(77)

def kill(name, s):
    print(f"terminating {name} ...")
    s.terminate()
    s.wait()
    print("terminated!")


def startSandbox(dbname="sandbox-test.sqlite3"):
    db_full_path = str(Path.cwd() / dbname)
    check_call(["rm", "-f", db_full_path])
    check_call(["../gradlew", "-p", "..", "sandbox:assemble"])
    checkPort(5000)
    sandbox = Popen(
        ["../gradlew", "-p", "..", "sandbox:run", "--console=plain", "--args=serve --db-name={}".format(db_full_path)],
        stdin=DEVNULL,
        stdout=open("sandbox-stdout.log", "w"),
        stderr=open("sandbox-stderr.log", "w"),
    )
    atexit.register(lambda: kill("sandbox", sandbox))
    for i in range(10):
        try:
            get("http://localhost:5000/")
        except:
            if i == 9:
                stdout, stderr = nexus.communicate()
                print("Sandbox timed out")
                print("{}\n{}".format(stdout.decode(), stderr.decode()))
                exit(77)
            sleep(2)
            continue
        break


def startNexus(dbname="nexus-test.sqlite3"):
    db_full_path = str(Path.cwd() / dbname)
    check_call(["rm", "-f", "--", db_full_path])
    check_call(
        ["../gradlew", "-p", "..", "nexus:assemble",]
    )
    check_call(
        [
            "../gradlew",
            "-p",
            "..",
            "nexus:run",
            "--console=plain",
            "--args=superuser admin --password x --db-name={}".format(db_full_path),
        ]
    )
    checkPort(5001)
    nexus = Popen(
        [
            "../gradlew",
            "-p",
            "..",
            "nexus:run",
            "--console=plain",
            "--args=serve --db-name={}".format(db_full_path),
        ],
        stdin=DEVNULL,
        stdout=open("nexus-stdout.log", "w"),
        stderr=open("nexus-stderr.log", "w"),
    )
    atexit.register(lambda: kill("nexus", nexus))
    for i in range(80):
        try:
            get("http://localhost:5001/")
        except:
            if i == 79:
                nexus.terminate()
                print("Nexus timed out")
                exit(77)
            sleep(1)
            continue
        break
    return nexus
