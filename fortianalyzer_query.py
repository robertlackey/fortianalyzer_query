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

url = "***ENTER URL/IP HERE***/jsonrpc" #ENTER THE URL OF YOUR FORTIANALYZER
headers = {
    'Vary': "Cookie,Accept-Encoding",
    'Content-Type': "application/json"
}

username= raw_input("enter your username: ")
password = getpass.getpass("enter your password: ")

now = datetime.datetime.now()
now_format = now.strftime("%Y-%m-%d %H:%M")
last_hour_date_time = datetime.datetime.now() - datetime.timedelta(hours = 1)
last_hour_date_time_format =  last_hour_date_time.strftime("%Y-%m-%d %H:%M")

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

def main():
    device = [
    'DEVICE00',
    'DEVICE01'
    ] #ENTER YOUR DEVCIES HERE

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
    class0.run_data(uri, device[0], logtype[0]) #ENTER DEVICE AND LOGTYPE THAT YOU WANT TO SEARCH
    class0.fetch_data(uri)
    class0.logout()

if __name__=='__main__':
    main()
    
