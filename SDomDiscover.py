#!/usr/bin/env python3

# Libraries
import signal
import requests
import sys
import re
import json
import argparse
import dns.zone
import dns.resolver
import pydig
from time import sleep
import pdb

# Output Colours
class c:
    PURPLE = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    UNDERLINE = '\033[4m'

# Ctrl + C Exit Function
def ctrl_c(sig, frame):
    sys.exit(c.RED + "\n[!] Interrupt handler received, exiting...\n" + c.END)

signal.signal(signal.SIGINT, ctrl_c)

# Banner Function
def banner():
    print(c.YELLOW + '                _____                   ')
    print('             .-"     "-.                ')
    print('            / o       o \               ')
    print('           /   \     /   \              ')
    print('          /     )-"-(     \             ')
    print('         /     ( 6 6 )     \            ')
    print('        /       \ " /       \           ')
    print('       /         )=(         \    - By D3Ext')
    print('      /   o   .--"-"--.   o   \         ')
    print('     /    I  /  -   -  \  I    \        ')
    print(' .--(    (_}y/\       /\y{_)    )--.    ')
    print('(    ".___l\/__\_____/__\/l___,"    )   ')
    print(' \                                 /    ')
    print('  "-._      o O o O o O o      _,-"     ')
    print('      `--Y--.___________.--Y--\'        ')
    print('         |==.___________.==|            ')
    print('         `==.___________.==\'           ' + c.END)

# Argument parser Function
def parseArgs():

    p = argparse.ArgumentParser(description="SDomDiscover - Silent Domain Discoverer - Abusing SSL transparency")
    p.add_argument("-d", "--domain", help="domain to search its subdomains", required=True)
    p.add_argument("-a", "--axfr", help="try a domain zone transfer attack", action='store_true', required=False)
    p.add_argument("-m", "--mail", help="try to enumerate mail servers", action='store_true', required=False)
    p.add_argument('-e', '--extra', help="look for extra dns information", action='store_true', required=False)
    p.add_argument("-n", "--nameservers", help="try to enumerate the name servers", action='store_true', required=False)
    p.add_argument("-i", "--ip", help="it reports the ip or ips of the domain", action='store_true', required=False)
    p.add_argument('-6', '--ipv6', help="enumerate the ipv6 of the domain", action='store_true', required=False)
    p.add_argument("-o", "--output", help="file to store the scan output", required=False)
    p.add_argument("--all", help="perform all the enumeration at once", action='store_true', required=False)
    p.add_argument("--version", help="display the script version", action='store_true', required=False)

    return p.parse_args()

# Nameservers Function 
def ns_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Trying to discover valid name servers...\n" + c.END)
    sleep(0.2)
    data = pydig.query(domain, 'NS')

    if data:
        for ns in data:
            l = len(ns)
            ns = ns[:l-1]
            print(c.YELLOW + ns + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# IPs discover Function
def ip_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering IPs of the domain...\n" + c.END)
    sleep(0.2)
    data = pydig.query(domain, 'A')

    if data:
        for ip in data:
            print(c.YELLOW + ip + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Extra DNS info Function
def txt_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Enumerating extra DNS information...\n" + c.END)
    sleep(0.2)
    data = pydig.query(domain, 'TXT')

    if data:
        for info in data:
            print(c.YELLOW + info + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

def ipv6_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Getting ipv6 of the domain...\n" + c.END)
    sleep(0.2)
    data = pydig.query(domain, 'AAAA')
    
    if data:
        for info in data:
            print(c.YELLOW + info + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Mail servers Function
def mail_enum(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Finding valid mail servers...\n" + c.END)
    sleep(0.2)
    data = pydig.query(domain, 'MX')

    if data:
        for mail_output in data:
            mail_output = mail_output.split(' ')[1]
            l = len(mail_output)
            mail_servers = mail_output[:l-1]
            print(c.YELLOW + mail_servers + c.END)
    else:
        print(c.YELLOW + "Unable to enumerate" + c.END)

# Domain Zone Transfer Attack Function
def axfr(domain):
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Starting Domain Zone Transfer attack...\n" + c.END)
    sleep(0.2)
    ns_answer = dns.resolver.resolve(domain, 'NS')
    for server in ns_answer:
        print(c.YELLOW + "[*] Found NS: {}".format(server) + c.END)
        ip_answer = dns.resolver.resolve(server.target, 'A')
        for ip in ip_answer:
            print(c.YELLOW + "[*] IP for {} is {}".format(server, ip) + c.END)
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(str(ip), domain))
                for host in zone:
                    print(c.YELLOW + "[" + c.END + c.GREEN + "+" + c.END + c.YELLOW + "] Found Host: {}".format(host) + c.END)
            except Exception as e:
                print(c.YELLOW + "[" + c.END + c.RED + "-" + c.END + c.YELLOW + "] NS {} refused zone transfer!".format(server) + c.END)
                continue

# Main Domain Discoverer Function
def SDom(domain,filename):
    banner()
    print(c.BLUE + "\n[" + c.END + c.GREEN + "+" + c.END + c.BLUE + "] Discovering valid subdomains...\n" + c.END)
    sleep(0.1)

    r = requests.get("https://crt.sh/?q=" + domain + "&output=json", timeout=20)
    formatted_json = json.dumps(json.loads(r.text), indent=4)
    domains = re.findall(r'"common_name": "(.*?)"', formatted_json)

    doms = []

    raw_doms = sorted(set(domains))
    for dom in raw_doms:
        if dom.endswith(domain):
            doms.append(dom)

    if filename != None:
        f = open(filename, "a")

    # Print the domains in a table format depending the domain length
    print(c.YELLOW + "+" + "-"*39 + "+")
    for value in doms:
        if not value.startswith('*' + "." + domain):

            if len(value) >= 10 and len(value) <= 14:
                l = len(value)
                print("| " + value + "    \t\t\t|")
                if filename != None:
                    f.write(value + "\n")

            if len(value) >= 15 and len(value) <= 19:
                l = len(value)
                print("| " + value + "\t\t\t|")
                if filename != None:
                    f.write(value + "\n")

            if len(value) >= 20 and len(value) <= 24:
                l = len(value)
                print("| " + value + "   \t\t|")
                if filename != None:
                    f.write(value + "\n")

            if len(value) >= 25 and len(value) <= 29:
                l = len(value)
                print("| " + value + "\t\t|")
                if filename != None:
                    f.write(value + "\n")

    print("+" + "-"*39 + "+" + c.END)
    print(c.YELLOW + "\nTotal discovered sudomains: " + str(len(doms) - 1) + c.END)

    if filename != None:
        f.close()
        print(c.BLUE + "\n[+] Output stored in " + filename)

# Program workflow starts here
if __name__ == '__main__':

    # If --version is passed
    if "--version" in sys.argv:
        print("\nSDomDiscover v1.0 - By D3Ext")
        print("Contact me: <d3ext@proton.me>\n")
        sys.exit(0)

    parse = parseArgs()

    # If --output is passed
    if parse.output:
        store_info=1
        filename = parse.output
    else:
        filename = None

    # Check passed enumeration parameters
    if parse.domain and parse.all:
        domain = parse.domain
        if domain.startswith('https://'):
            domain = domain.split('https://')[1]

        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        SDom(domain,filename)
        axfr(domain)
        mail_enum(domain)
        ns_enum(domain)
        ip_enum(domain)
        ipv6_enum(domain)
        txt_enum(domain)

        sys.exit(0)

    if parse.domain:
        domain = parse.domain
        if domain.startswith('https://'):
            domain = domain.split('https://')[1]

        if domain.startswith('http://'):
            domain = domain.split('http://')[1]

        SDom(domain,filename)

        if parse.axfr:
            axfr(domain)

        if parse.mail:
            mail_enum(domain)

        if parse.nameservers:
            ns_enum(domain)

        if parse.ip:
            ip_enum(domain)

        if parse.ipv6:
            ipv6_enum(domain)

        if parse.extra:
            txt_enum(domain)

        sys.exit(0)

