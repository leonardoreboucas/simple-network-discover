import time
import nmap
import json
import os.path
import subprocess

# Required install
# - OS: nmap pip3 sshpass
# - Python3: python-nmap

# Configuration
sleep_time = 3
network = '10.0.20.0/28'
catalog_file = 'catalog.json'
username = 'discovery'
password = 'discovery'

def get_catalog():
    catalog = []
    if not os.path.isfile(catalog_file):
        with open(catalog_file, 'w') as f:
            json.dump([], f)
    with open(catalog_file) as f:
        catalog = json.load(f)
    return catalog

def discover(catalog):
    catalog_macs = []
    for host in catalog:
        if "mac" in host["addresses"]:
            catalog_macs.append(host["addresses"]["mac"])
    nm = nmap.PortScanner()
    nm.scan(hosts = network, arguments='-nsP')
    discovered_hosts = []
    for host in nm.all_hosts():
        discovered_hosts.append(nm[host])
    for host in discovered_hosts:
        if "mac" in host["addresses"] and host["addresses"]["mac"] not in catalog_macs:
            catalog.append(host)
    return catalog

def get_metric(ip, metric):
    if metric not in ["cpu", "memory", "storage"]:
       return False
    if metric == "memory":
        cmd = "free --mega | awk 'NR!=1 {print $4}' | head -1"
    if metric == "storage":
        cmd = "df / | awk 'NR!=1 {print $4}'"
    if metric == "cpu":
        cmd = "nproc --all"
    res = subprocess.Popen(f"sshpass -p {password} ssh  -o StrictHostKeyChecking=no {username}@{ip} {cmd}", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
    return res[0].decode('utf8').replace('\n','')     

def enrich(catalog):
    for host in catalog:
        ip = host["addresses"]["ipv4"]
        host["memory"] = get_metric(ip, "memory")
        host["storage"] = get_metric(ip, "storage")
        host["cpu"] = get_metric(ip, "cpu")
    return catalog

def persist(catalog):
    with open(catalog_file, 'w') as f:
        json.dump(catalog, f)

def main():
    catalog = get_catalog()
    while True:
        print("Discovering...",end="\r")
        count_before = len(catalog)
        catalog = discover(catalog)
        catalog = enrich(catalog)
        persist(catalog)
        count_after = len(catalog)
        print ("Discovering... ", str(count_after-count_before), " hosts found", end="\n")
        time.sleep(3)
    
main()