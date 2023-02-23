import subprocess
import source
import os


COMMANDS = {
    "list" : "ls",
    "stat" : "stat"
}

def sink():
    env = source.source()
    subprocess.call(env)
    os.system(env)


def sink1():
    action = source.source2()
    subprocess.call(["application", action])
