import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import sys
import argparse
import datetime
import re
import getpass
import json
import time

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

url = "***ENTER URL/IP HERE***/jsonrpc"# ENTER URL OR IP OF THE FORTIANALYZER
headers = {
    'Vary': "Cookie,Accept-Encoding",
    'Content-Type': "application/json"
}

username= raw_input("enter your username: ")
password = getpass.getpass("enter your password: ")

now = datetime.datetime.now()
now_format = now.strftime("%Y-%m-%d %H:%M")
last_hour_date_time = datetime.datetime.now() - datetime.timedelta(hours = 1)#DEFINING LAST HOUR VARIABLE
last_hour_date_time_format =  last_hour_date_time.strftime("%Y-%m-%d %H:%M")#FORMATING TIME FOR FORTIANALYZER

class fortianalyzer:

    def __init__(self, url, verify=False):
        self.url = url
        self.verify = verify

    def login(self):
        with requests.Session() as s:
            #payload as described in the fortianalyzer json api documentation
            #Username and password are formatted to add double quotes around the values
            login_payload="""{
                \n \"method\":\"exec\",
                \n \"params\":[ 
                \n {
                \n \"url\":\"/sys/login/user\",
                \n \"data\": {
                \n \"user\": """ + '"{}"'.format(username) + """,
                \n \"passwd\": """ +  '"{}"'.format(password) + """
                \n }
                \n }
                \n ],
                \n \"id\":1
                \n } """
            #regex to look for the beginning of the output from the login
            #looking for everything before "session:"
            r = re.compile("(..*\w*.],.)")
            #looking the last character "}"
            reg = re.compile("(\S.})")
            conn = s.request("POST", self.url, verify=False, headers=headers, data=login_payload)
            #removing everything before "session:"
            #assigning to a variable to be used in other functions
            self.session = re.sub(r, "", conn.text)
            #removing the last character "}"
            self.session = re.sub(reg, "", self.session)
            print conn.text
            print "#" *100

    def run_data(self, uri, device, logtype):
        payload ="""
        {
        \n  \"jsonrpc\": \"2.0\",
        \n  \"method\": \"run\",
        \n  """ + self.session + """\",
        \n  \"id\": \"1\",
        \n  \"params\": [
        \n    {
        \n      \"uri\": """ +  '"{}"'.format(uri) + """,
        \n      \"adom\": \"root\",
        \n      \"apiver\": 1,
        \n      \"uri-params\": {
        \n        \"devices\": [
        \n          """ + '"{}"'.format(device) + """,
        \n        ],
        \n        \"period\": {
        \n          \"from\": """ +  '"{}"'.format(last_hour_date_time_format) + """,
        \n          \"to\": """ +  '"{}"'.format(now_format) + """
        \n        },
        \n        \"filters\": [
        \n          \"*\",
        \n        ],
        \n        \"filter-logic\": \"any\",
        \n        \"logtype\":""" + '"{}"'.format(logtype) + """,
        \n        \"count\": 20,
        \n        \"sort-by\": {
        \n          \"field\": \"\",
        \n          \"desc\": true
        \n        },
        \n        \"interim-result\": true,
        \n        \"compact-result\": true
        \n      }
        \n    }
        \n  ]
        \n}
        """
        with requests.Session() as s:
            r = re.compile("^(?:{..\w*\S.*{.)")
            reg = re.compile("(\D})")
            conn = s.request("POST", self.url +"/fazapi", verify=False, headers=headers, data=payload)
            self.request_id = re.sub(r, "", conn.text)
            self.request_id = re.sub(reg, "", self.request_id)
            print conn.text
            print "#" *100

    def fetch_data(self, uri):
        time.sleep(5)
        payload = """{
            \n \"jsonrpc\":\"2.0\",
            \n \"method\":\"fetch\",
            \n  """ + self.session + """\",
            \n \"id\": \"1\",
            \n \"params\": [
            \n {
            \n \"uri\": """ +  '"{}"'.format(uri) + """,
            \n \"adom\": \"root\",
            \n \"apiver\": 1,
            \n """ + self.request_id + """
            \n  }
            \n ]
            \n }
            """
        with requests.Session() as s:
            conn = s.request("POST", self.url +"/fazapi", verify=False, headers=headers, data=payload)
            print json.dumps(conn.json(), indent=2, sort_keys=True)
            print "#" *100

    def logout(self):
        with requests.Session() as s:
            payload = """{
                \n \"method\":\"exec\",
                \n \"params\":[ 
                \n {
                \n \"url\": \"/sys/logout\"
                \n } 
                \n ],
                \n \"id\": 1,
                \n """ + self.session +"\"}"
            conn = s.request("POST", self.url, verify=False, headers=headers, data=payload)
            print conn.text
def usage():
    print "usage = python program.py <number1> <number>2\n"
    print "<number1> = Devices:\n0=DEVICE00\n1=DEVICE01"
    print "<number2> = logtype:\n0=app-ctrl\n1=attack\n2=content\n3=dlp\n4=emailfilter\n5=event"
    print "6=generic\n7=history\n8=im\n9=traffic\n10=virus\n11=voip\n12=webfilter\n13=netscan"
    print "14=fct-event\n15=fct-traffic\n16=fct-netscan\n17=waf\n18=gtp"

def main(arg1, arg2):
    device = [
    'DEVICE00',
    'DEVICE01'#ENTER YOUR DEVICES HERE
        ]
    logtype = [
        'app-ctrl',
        'attack',
        'content',
        'dlp',
        'emailfilter',
        'event',
        'generic',
        'history',
        'im',
        'traffic',
        'virus',
        'voip',
        'webfilter',
        'netscan',
        'fct-event',
        'fct-traffic',
        'fct-netscan',
        'waf',
        'gtp'
    ]
    uri = "/faz/fortiview/threat"
    class0 = fortianalyzer(url)
    class0.login()
    try:
        if len(arg1) == 2 and len(arg2) == 1:
            #defining device argparser
            dev = argparse.ArgumentParser()
            #defining logtype argparer
            lt = argparse.ArgumentParser()
            #passing in a number between 0 and 7.
            dev.add_argument('devices', nargs="+", type=int, choices=xrange(0, 1))#CHANGE VALUE OF 1 TO NUMBER OF DEVICES
            lt.add_argument('logtype', nargs="+", type=int, choices=xrange(0, 18))
            class0.run_data(uri, dev.parse_args(arg1), lt.parse_args(arg2))
        elif len(arg1) < 2 and len(arg2) < 1:
            usage()
            sys.exit()
        else: 
            print "Not enough arguments"
            usage()
            sys.exit()
    except Exception:
        print "error occurred"
        sys.exit()
    class0.fetch_data(uri)
    class0.logout()

if __name__=='__main__':
    print sys.argv
    print len(sys.argv[1:])
    print len(sys.argv[2:])
    main(sys.argv[1:], sys.argv[2:])
    
