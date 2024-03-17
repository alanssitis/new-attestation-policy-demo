#!/usr/bin/env python3

import os
import sys
import shlex
import subprocess
import argparse

NO_PROMPT = False
TESTREPO = "in-toto/ite-4-demo-test-repo"
PWD = os.getcwd()
PROJECT_DIR = os.path.join(PWD, "project")
MALICIOUS_FILES_DIR = os.path.join(PWD, "malicious_files")


def print_command(command):
    print(f'\n$ {command}')


def prompt_key(prompt):
    if NO_PROMPT:
        print("\n" + prompt)
        return
    inp = False
    while inp != "":
        try:
            inp = input("\n{} -- press the <enter> key to continue".format(prompt))
        except Exception:
            pass


def clean():
    # reset project
    os.chdir(PROJECT_DIR)
    subprocess.call(shlex.split("make clean"))
    os.chdir(PWD)


def show_project_demo():

    prompt_key("Show the 'project' file structure.")
    tree_project_cmd = "tree project"
    print_command(tree_project_cmd)
    subprocess.call(shlex.split(tree_project_cmd))
    os.chdir(PROJECT_DIR)

    prompt_key("Build the 'project'.")
    make_cmd = "make"
    print_command(make_cmd)
    subprocess.call(shlex.split(make_cmd))

    prompt_key("Run the executable.")
    run_project_cmd = "./testy"
    print_command(run_project_cmd)
    subprocess.call(shlex.split(run_project_cmd))
    os.chdir(MALICIOUS_FILES_DIR)

    prompt_key("Inject malicious object file.")
    print_command(make_cmd)
    subprocess.call(shlex.split(make_cmd))
    os.chdir(PROJECT_DIR)

    prompt_key("Build the project again.")
    print_command(make_cmd)
    subprocess.call(shlex.split(make_cmd))

    prompt_key("Run the executable again.")
    run_project_cmd = "./testy"
    print_command(run_project_cmd)
    subprocess.call(shlex.split(run_project_cmd))

    os.chdir(PWD)


def supply_chain():

    prompt_key("TODO")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-n",
                        "--no-prompt",
                        help="No prompt.",
                        action="store_true")
    parser.add_argument("-c",
                        "--clean",
                        help="Remove files created during demo.",
                        action="store_true")
    args = parser.parse_args()

    if args.clean:
        clean()
        sys.exit(0)

    if args.no_prompt:
        global NO_PROMPT
        NO_PROMPT = True

    show_project_demo()
    supply_chain()


if __name__ == '__main__':
    main()
