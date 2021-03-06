# Deep-Proxy-Checker
Script that checks proxies and provides some additional info.
Supports Multi-Threading when checking proxies from a file.
Information incudes: WHOIS lookup, ptdr, ip type (ipv4 or ipv6), ip converted to int, static or dynamic proxy, response time, total retries.
Output format:
proxy : proxy_ip : proxy_ip_int : ip_type : works or not : retries : response_time : error_requests : static_or_dynamic : time_stamp
### Getting started:
Clone the repo to your computer.
```
cd project-folder
```
Create a virtual environment:
```
virtualenv venv
```
Install requirements:
```
pip install -r requirements.txt
```
# Usage:
1- Single proxy test:
```
checker.py <proxy> -t <timeout> -e <type>
```
2- Multiple proxy test with Threading:
```
checker.py -f <file_name> -n <Number_of_threads> -t <timeout> -e <type>
```
type is the proxy protocol, either http, socks4 or sock5, and you can use auto to let the script detect the protocol.
 
PS: This script was tested On python3.8
# Contributing:

> To get started...

### Step 1

- **Option 1**
    - 🍴 Fork this repo!

- **Option 2**
    - 👯 Clone this repo to your local machine using `https://github.com/AbdelH2O/Deep-Proxy-Checker.git`

### Step 2

- **HACK AWAY!** 🔨🔨🔨

### Step 3

- 🔃 Create a new pull request using <a href="https://github.com/AbdelH2O/Deep-Proxy-Checker/compare/" target="_blank">`https://github.com/AbdelH2O/Deep-Proxy-Checker/compare/`</a>.

---
