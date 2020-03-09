import os
import sys
import time
import re
from termcolor import cprint
from tabulate import tabulate
from colorama import Fore
from colorama import Style

def banner():
    with open('banner.txt', 'r',encoding = "utf8") as f:
        data = f.read()

        print(f'{Fore.GREEN}%s{Style.RESET_ALL}' % data)
        print("Providing you with Remote Code Execution Scanner for PHP projects")
        print("Author : Harshil Shah (@harshil-shah004)")

if len(sys.argv) != 3:
    cprint("[+] Usage : ./{0} path extension".format(sys.argv[0]), "red")
    cprint("[+] Example : ./{0} /var/www/plugin php".format(sys.argv[0]), "red")
    sys.exit(0)

path = sys.argv[1]
extension = sys.argv[2]
final_files = []
reg_php = '''\((.*)\);'''		# regular expression for php
reg_py = '''\((.*)\)'''			# regular expression for python
unsafe_php = ["system", "shell_exec", "exec", "passthru", "eval"]
unsafe_python = ["os.system", "os.popen", "subprocess.Popen", "subprocess.call", "subprocess.run"]	# 2 unsafe lists used - php and python

def spider(script_path):
    if os.path.exists(path) is False:
        cprint("[-]Directory not exist", "red")
        sys.exit(0)
    cprint("[+] Scanning started for the script ..", "green")

    if extension=='php':							# Seperate code blocks for file collection based on the extension given by the user
    	for root, dirs, files in os.walk(script_path, topdown=False):
                for fi in files:
                    dfile = os.path.join(root, fi)
                    if dfile.endswith(".php"):
                        final_files.append(dfile)
    	cprint("[+] {0} php files found".format(len(final_files)), "green")

    elif(extension=='py'):							# For Python files
        for root, dirs, files in os.walk(script_path, topdown=False):
                for fi in files:
                    dfile = os.path.join(root, fi)
                    if dfile.endswith(".py"):
                        final_files.append(dfile)
        cprint("[+] {0} python files found".format(len(final_files)),"green")

    else :									# php/py are the only valid arguments
        cprint("[-] {0} format is not supported.format(extension)","red")
        cprint("[-] Valid formats : php / py","red")
        sys.exit(0)

def scanner(files_list):
    results = []

    if extension=='php':	# Getting regex and list of unsafe functions for php
        unsafe = unsafe_php
        reg = reg_php
    elif extension=='py':	# Getting regex and list of unsafe functions for python
        unsafe=unsafe_python
        reg = reg_py
    for fi in files_list:
        f = open(fi, "r")
        data = f.readlines()
        for line in data:
            linen = data.index(line) + 1
            for unsafe_function in unsafe:
                line_no = line.strip("\n")
                final_reg = unsafe_function + reg
                if bool(re.search(final_reg, line_no)):
                    file_result = [fi, unsafe_function, linen]
                    results.append(file_result)
    print(tabulate(results,
     headers=['File Name', 'Function Name', "Line Number"],
     tablefmt='psql', numalign="center", stralign="center"))


if __name__ == "__main__":
    banner()
    spider(path)
    scanner(final_files)



