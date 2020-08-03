import requests
import sys
import mysql.connector
import getopt
import ipaddress
import datetime
import threading
import time
import os.path
from ipwhois import IPWhois
from dns import resolver
from dns import reversename
import json

f = open("output.txt", 'a')
progress = 0
# MySQL credentials and database name
host = "localhost"
username = "root"
password = "rabatsale@1"
database = "mydatabase"


# Simple function to that returns a connection to MySQL DB
def conn(host, username, password, database):
    return mysql.connector.connect(
        host=host,
        user=username,
        password=password,
        database=database
    )


# Function to insert data into Database
def insert(mydb, value1, value2, value3, value4, value5):
    mycursor = mydb.cursor()
    # change table name
    sql = "INSERT INTO table_name (org_name, cidr, ptr, address, whois) VALUES (%s, %s, %s, %s, %s, %s)"
    val = (value1, value2, value3, value4, value5)
    mycursor.execute(sql, val)
    mydb.commit()


# Function that determines the IP_TYPE (ipv4 or ipv6)
def ip_kind(addr):
    return ipaddress.ip_address(addr).version


def check_proxy(proxy, time_out, proto, total):
    # If the protocol is auto, we need to determine the correct protocol to use
    if proto == "auto":
        for protocol in ['http', 'socks4', 'socks5']:
            prox = protocol + '://' + proxy
            try:
                req = requests.get("https://www.google.com/", proxies={"http": prox, "https": prox})
                if not req:
                    continue
                proto = protocol
                break
            except TimeoutError:
                pass
    prox = proto + '://' + proxy
    ok = "FAILED"
    static = "Static"
    ip_add = ""
    step = -1
    errors = 0
    response_time = -1
    # running 3 requests to determine if the proxy works, and if it has the same IP on every request
    for i in range(1, 4):
        try:
            r = requests.get("https://api.ipify.org/", proxies={"http": prox, "https": prox}, timeout=int(time_out)*i)
            if response_time == -1:
                response_time = r.elapsed.total_seconds()

            if r.text != ip_add and ip_add != '':
                static = "Dynamic"
            ip_add = str(r.text)
            if step == -1:
                step = i
            ok = "OK"
        except (TimeoutError, requests.exceptions.ProxyError):
            errors += 1
    if errors < 3:
        # Getting the IP_TYPE and converting the IP address into an INT
        if ip_kind(ip_add) == 4:
            ip_type = "ipv4"
            int_address = str(int(ipaddress.IPv4Address(str(ip_add))))
        else:
            ip_type = "ipv6"
            int_address = str(int(ipaddress.IPv6Address(str(ip_add))))
        # "solution" is the result to be added to the output
        solution = proxy + str(ip_add) + ":" + int_address + ":" + ip_type + ":" + ok + ":" + str(step) + "x:" \
            + str(response_time) + ":" + str(errors) + ":" + static + ":" +\
            datetime.datetime.utcnow().strftime("%a/%b/%d/%H;%M;%S/%Y")
        obj = IPWhois(ip_add)
        results = obj.lookup_rdap()
        cidr = results['asn_cidr']
        with open(ip_add + ".json", 'w') as y:
            y.write(json.dumps(results, sort_keys=True, indent=4))
        rr = results["objects"]
        tt = rr[list(results["objects"].keys())[0]]
        ff = tt["contact"]
        gg = ff["address"]
        er = gg[0]
        okk = er['value']
        addr = reversename.from_address("172.217.21.14")
        org = results['asn_description']
        ptr = resolver.resolve(addr, "PTR")[0]
        # mydb = conn(host, username, password, database)
        # insert(mydb, ptr, results, cidr, org, address)
    else:
        # "solution" is the result to be added to the output
        solution = proxy + ": : :" + ok + ":" + " :" \
                   + " " + ":" + str(errors) + ":" + " " + ":" + \
                   datetime.datetime.utcnow().strftime("%a/%b/%d/%H;%M;%S/%Y")
    # writing results to a txt file
    f.write(solution + '\n')
    # updating the current progress
    global progress
    progress += 1
    print("{}% Done!".format(progress/total*100))


arg = sys.argv[1:]
if len(arg) == 0:
    print('usage: checker.py <proxy> -t <timeout> -e <type>    or\n       checker.py -f <file_name> -n '
          '<Number_of_threads> -t <timeout> -e <type>')
    exit(0)
# checking if the script will get input from a file or if it's a single proxy to test
if arg[0] == '-f':
    argv = sys.argv[1:]
    arguments = {}
    # getting arguments
    try:
        # Define the getopt parameters
        opts, args = getopt.getopt(argv, 'f:n:t:e:', ['proxy_file', 'threads', 'timeout', 'type'])
        # Check if the options' length is 4
        if len(opts) != 4:
            print('usage: checker.py <proxy> -t <timeout> -e <type>    or\n       checker.py -f <file_name> -n '
                  '<Number_of_threads> -t <timeout> -e <type>')
        else:
            # Iterate the options and get the corresponding values
            for opt, arg in opts:
                arguments[opt] = arg
        # checking if the provided protocol is correct
        if arguments['-e'] != "auto" and arguments['-e'] != "http" and arguments['-e'] != "socks4" \
                and arguments['e'] != "socks5":
            print("<type> has to be either 'http' or 'socks4' or 'socks5' or 'auto'")
            exit(0)
        # checking if the provided proxy file exists
        if not os.path.isfile(arguments['-f']):
            print("File does not exist. Make sure to put the file in the same "
                  "folder as the script or provide an absolute path")
            exit(0)
        file = open(arguments['-f'])
        proxx = file.readlines()
        index = 0
        # creating threads to test the proxies
        while index < len(proxx):
            while True:
                # checking if we're not exceeding the maximum number of threads
                if threading.active_count() <= int(arguments['-n']):
                    ip = proxx[index][0:-1]
                    th = threading.Thread(target=check_proxy, args=(ip, arguments['-t'], arguments['-e'], len(proxx)))
                    th.start()
                    index += 1
                    break
                else:
                    # If we're at the limit, wait for 1 second (You can change the value down below as you want)
                    time.sleep(1)
    # Error getting arguments
    except getopt.GetoptError:
        print('usage: checker.py <proxy> -t <timeout> -e <type>    or\n       checker.py -f <file_name> -n '
              '<Number_of_threads> -t <timeout> -e <type>')
        sys.exit(2)
# testing one proxy only
else:
    ip = arg[0]
    argv = sys.argv[2:]
    arguments = {}
    try:
        # Define the getopt parameters
        opts, args = getopt.getopt(argv, 't:e:', ['timeout', 'type'])
        # Check if the options' length is 2
        if len(opts) != 2:
            print('usage: checker.py <proxy> -t <timeout> -e <type>    or\n       checker.py -f <file_name> -n '
                  '<Number_of_threads> -t <timeout> -e <type> yes')
        else:
            # Iterate the options and get the corresponding values
            for opt, arg in opts:
                arguments[opt] = arg
        if arguments['-e'] != "auto" and arguments['-e'] != "http" and arguments['-e'] != "socks4"\
                and arguments['-e'] != "socks5":
            print("<type> has to be either 'http' or 'socks4' or 'socks5' or 'auto'")
            exit(0)
        # no need to use multi-threading since we're only testing one proxy
        check_proxy(ip, arguments['-t'], arguments['-e'], 1)
    except getopt.GetoptError:
        # Print something useful
        print('usage: checker.py <proxy> -t <timeout> -e <type>    or\n       checker.py -f <file_name> -n '
              '<Number_of_threads> -t <timeout> -e <type>')
        sys.exit(2)
