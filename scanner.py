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
reg = '''\((.*)\);'''
unsafe = ["system", "shell_exec", "exec", "passthru", "eval"]

def spider(script_path):
    if os.path.exists(path) is False:
        cprint("[-]Directory not exist", "red")
        sys.exit(0)
    cprint("[+] Scanning started for the script ..", "green")
    for root, dirs, files in os.walk(script_path, topdown=False):
            for fi in files:
                dfile = os.path.join(root, fi)
                if dfile.endswith(".php"):
                    final_files.append(dfile)
    cprint("[+] {0} php files found".format(len(final_files)), "green")

def scanner(files_list):
    results = []
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