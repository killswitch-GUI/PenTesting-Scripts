#!/usr/bin/env python
import os
import sys
import threading
import multiprocessing
import Queue
import json
import requests

global IP_List


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

def whois2(ip_queue, results_queue):
    while True:
        cont = True
        connect_timeout = float(6.05)
        read_timeout = 5
        value = "alex"
        #Simple whois query for location
        ip = ip_queue.get()
        if ip is None:
            # Break out of the while loop to terminate Sub-Procs
            break
        try:
            agent = (requests.post(url='http://www.telize.com/geoip/'+ ip.rstrip() +'', timeout=(connect_timeout, read_timeout)).json())
            # ex United States
            country = str(agent['country'])
            # State for US
            region = str(agent['region'])
            # City whithin state
            city = str(agent['city'])
        except:
            cont = False
        try:
            if cont:
                geo_data = {'country':country, 'region':region, 'city':city}
                output = str(ip.rstrip())
                output += ' (' + geo_data["country"] + ':' + geo_data["region"] + ':' + geo_data["city"] + ')' + '\n'
                print ("{0} ({1}:{2}:{3})").format(str(ip.strip()), geo_data["country"], geo_data["region"], geo_data["city"])
                #print str(ip.rstrip()) + ' ' + ' (' + geo_data["country"] + ':' + geo_data["region"] + ':' + geo_data["city"] + ')'
                results_queue.put(output)
        except:
            pass
    return

def whois_geo_lookup(ip_queue, results_queue):
    total_threads = 50
    for thread in range(total_threads):
        t3 = threading.Thread(target=whois2, args=(ip_queue,results_queue))
        t3.daemon = True
        t3.start()
    t3.join()

def printer(results_queue):
    while True:
        # Get item an print to output file
        try:
            # Must set time out due to blocking, 
            item = results_queue.get(timeout=2)
            with open('iplist_output2.txt', "a") as myfile:
                myfile.write(item)
        except Exception as e:
            print e
            break
        #results_queue.task_done()
    return

def main():
    # Build Queue
    script_queue = multiprocessing.Queue()
    results_queue = multiprocessing.Queue()

    #lock = multiprocessing.Lock()
    #with lock:

    # Set time out for join method
    timeout = float(0.1)
    # Define max Threads and IP list
    total_proc = 8 
    IP_List = file_handle()
    # Places all the IP's in the list into the Queue
    for IP in IP_List:
        script_queue.put(IP)

    for i in xrange(total_proc):
        script_queue.put(None)
    # Generate threads for worker
    procs = []
    for thread in range(total_proc):
        procs.append(multiprocessing.Process(target=whois_geo_lookup, args=(script_queue,results_queue,)))
    
    for p in procs:
        p.daemon = True
        p.start()
    # Removed for loop due to time and uneeded function, Set Float to reduce time of clossing, TESTING NEEDED!
    for p in procs: 
        p.join(timeout)
    #Launches a single thread to output results
    t2 = threading.Thread(target=printer, args=(results_queue,))
    t2.daemon = True
    t2.start()
    t2.join()
    #Wait for queue to empty
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

