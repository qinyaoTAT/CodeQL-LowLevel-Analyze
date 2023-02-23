import os
import subprocess


def bad():
    env = os.getenv('HOME')
    subprocess.call([env])
    subprocess.call(env)
    os.system(env)

    env_new = os.path.join(env, 'demo')
    subprocess.call([env_new])
    os.system(env_new)


def source():
    env = os.getenv('HOME')
    return env


def sink():
    env = source()
    subprocess.call([env])
    os.system(env)


    env_new = 'ls ' + env
    subprocess.call([env_new])
    os.system(env_new)
