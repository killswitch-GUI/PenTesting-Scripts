#!/usr/bin/env python
import os
import sys
import socket
import argparse
import threading
import Queue
import json
import requests

global IP_List
global results_queue
results_queue = Queue.Queue()

def file_handle():
    try:
        IP_output = open('iplist_output.txt', 'w+')
        IP_output.close()
        print "[*] Output File created"
    except:
        print "[!] Couldnt create file check permissions"
        sys.exit(0)
    try:
        with open("iplist2.txt") as f:
            IP_List = f.readlines()
        f.close()
        # Caculate the ammount of IP's loaded
        with open("iplist2.txt") as myfile:
            count = sum(1 for line in myfile)
        print '[*] IP List loaded with:', count, " IP's"
    except:
        print "[!] Couldnt open file check file path!"
        sys.exit(0)
    return IP_List

def whois_geo_lookup(ip_queue):
    connect_timeout = float(5.05)
    read_timeout = 20
    while True:
        #Simple whois query for location
        ip = ip_queue.get()
        try:
            agent = (requests.post(url='http://www.telize.com/geoip/'+ ip.rstrip() +'', timeout=(connect_timeout, read_timeout))).json()
            # ex United States
            country = str(agent['country'])
            # State for US
            region = str(agent['region'])
            # City whithin state
            city = str(agent['city'])
        except:
            pass
        try:
            geo_data = {'country':country, 'region':region, 'city':city}
            output = str(ip.rstrip())
            output += ' (' + geo_data["country"] + ':' + geo_data["region"] + ':' + geo_data["city"] + ')' + '\n'
            print ("{0} ({1}:{2}:{3})").format(str(ip.strip()), geo_data["country"], geo_data["region"], geo_data["city"])
            #print str(ip.rstrip()) + ' ' + ' (' + geo_data["country"] + ':' + geo_data["region"] + ':' + geo_data["city"] + ')'
            results_queue.put(output)
        except:
            pass
        ip_queue.task_done()
    return 

def printer(results_queue):
    while True:
        # Get item an print to output file
        try:
            item = results_queue.get()
            with open('iplist_output2.txt', "a") as myfile:
                myfile.write(item)
        except:
            pass
        results_queue.task_done()

def main():
    # Build Queue
    script_queue = Queue.Queue()
    # Define max Threads and IP list
    total_threads = 100
    IP_List = file_handle()
    # Places all the IP's in the list into the Queue
    for IP in IP_List:
        script_queue.put(IP)
    # Generate threads for worker
    for thread in range(total_threads):
        t = threading.Thread(target=whois_geo_lookup, args=(script_queue,))
        t.daemon = True
        t.start()
    #Start up
    print "[*] starting to scan.."
    #Launches a single thread to output results
    t2 = threading.Thread(target=printer, args=(results_queue,))
    t2.daemon = True
    t2.start()
    #Wait for queue to empty
    script_queue.join() #blocking
    results_queue.join()
    print "[*] Scan Complete!"


if __name__ == "__main__":
        try:  
             main()
        except KeyboardInterrupt:
            print 'Interrupted'
            try:
                sys.exit(0)
            except SystemExit:
                os._exit(0)

