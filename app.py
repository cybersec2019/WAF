from flask import Flask
from blackListIP.blackListIP import *
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import logging
from notification.mailNotification import *
import webbrowser
from IPy import IP
import requests
from urllib.parse import unquote
import socket
import time
from pymongo import MongoClient
import re
from database.model import *
from http import cookies
app = Flask(__name__)

from mongoengine import connect

#Connect to WAF database
connect('WAF')
#Attach this url to your web application
url = ""
#TODO:
# YOU CAN USE CURL OR BURP OR ANY SOFTWARE THAT SUITE YOU TO TEST WAF
#Handle GET , HEAD , POST request

#Helper function
def setup_logger(name, log_file, level=logging.INFO):
    """To setup as many loggers as you want"""

    handler = logging.FileHandler(log_file)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)

    return logger
'''
def _check_valid_ipv4(ip):
    # Need precisely 3 dots and one slash /
    # Need to have form xxx.xxx.xxx.xxx/x
    # CIDR value can't be more than 32

    # Netmask can't be more than 255 and less than 0
    # first netmask can't be 0
    if (int(ip[0]) < 1 or int(ip[0]) > 255
            or int(ip[1]) < 0 or int(ip[1]) > 255
            or int(ip[2]) < 0 or int(ip[2]) > 255
            or int(ip[3]) < 0 or int(ip[3]) > 255):
        raise ValueError('Invalid ipaddress')
    return
'''
class S(BaseHTTPRequestHandler):

    log_file = setup_logger('log','logfile.log')
    input_file = setup_logger('log','input.log')
    sql_injection_word = []
    #Read in sql_injection_word
    with open('sql_injection_word', 'r') as infile:
        word = infile.readlines()
        for i in word:
            text = (i.split(' '))
            for j in text:
                sql_injection_word.append(j)

    def _html_not_found(self):
        self._set_headers(404)
        # self.wfile.write(self._html("Dude, you blocked from LynxServer"))
        with open("static/404.html", 'rb') as fh:
            html = fh.read()
            # html = bytes(html, 'utf8')
            self.wfile.write(html)
        self.log_format(404, "")
        return
    def _html_suspicious_request(self):
        self._set_headers(404)
        # self.wfile.write(self._html("Dude, you blocked from LynxServer"))
        with open("static/error.html", 'rb') as fh:
            html = fh.read()
            # html = bytes(html, 'utf8')
            self.wfile.write(html)
        self.log_format(404, "")
        return

    def _set_headers(self,res_code):
        self.send_response(res_code)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def _html(self, message):
        """This just generates an HTML document that includes `message`
        in the body. Override, or re-write this do do more interesting stuff.
        """
        content = f"<html><body><h1>{message}</h1></body></html>"
        return content.encode("utf8")  # NOTE: must return a bytes object!

    def log_format(self, res_code, body):
        log_data = "[" + str(self.log_date_time_string()) + "]" + " -- " + str(
            self.client_address[0]) + " -- " + str(self.client_address[1]) + " -- " + str(
            self.command) + " " + str(self.path) + " " + body + " " + self.request_version + " -- " + str(res_code) + "-"
        self.log_file.info(log_data)
        return

    #We can improve check_sql_injection to reduce false positive and increase accuratecy
    #This is header check
    def _check_sql_injection(self):
        #self.sql_injection_word
        #Need to process path
        #It wil have this form WHERE%20USER%FIND%20SOMETHING
        print(self.sql_injection_word)
        self.path = (' '.join(self.path.split("%20"))).lower()
        print(self.path)
        count = 0
        print(self.path)
        for i in self.sql_injection_word:
            if self.path.find(i.lower()) != -1:
                count = count + 1
            if count >= 3:
                #Log this request to our sql_injection_attack log
                return True
        return False
    def _check_XSS_attack(self):
        if "<IMG_SRC=" in self.path:
            return True
        elif "<b" in self.path:
            return True
        elif "<META HTTP-EQUIV=" in self.path:
            return True
        elif "<body>" in self.path:
            return True
        elif "<div" in self.path:
            return True
        elif "<script>" in self.path:
            return True
        elif "<style>" in self.path:
            return True
        elif "</style>" in self.path:
            return True
        elif "</body>" in self.path:
            return True
        elif ">" in self.path:
            return True
        elif "</script>" in self.path:
            return True
        elif "</style>" in self.path:
            return True
        elif "</style>" in self.path:
            return True
        else:
            return False
    #Check XSS attack
    def _check_body_XSS_attack(self,input):

        if "<IMG_SRC=" in input:
            return True
        elif "<b" in input:
            return True
        elif "<META HTTP-EQUIV=" in input:
            return True
        elif "<body>" in input:
            return True
        elif "<div" in input:
            return True
        elif "<script>" in input:
            return True
        elif "<style>" in input:
            return True
        elif "</style>" in input:
            return True
        elif "</body>" in input:
            return True
        elif ">" in input:
            return True
        elif "</script>" in input:
            return True
        elif "</style>" in input:
            return True
        elif "</style>" in input:
            return True
        else:
            return False

    def _check_header_injecion(self):

        return False

    def _check_body_injection(self):

        return False

    def _check_directory_traversal(self):
        m = re.search("/\.\.|2%f/",self.path)
        if m:
            print("Path traversal detection")
            return True
        return False
    def _check_suspicious_request(self):
        suspicious_ip_instance = Suspiciousips()
        #Check sql injection
        if self._check_sql_injection():
            suspicious_ip_instance.ip = self.client_address[0]
            suspicious_ip_instance.reason = "SQL injection"
            suspicious_ip_instance.save()
            return True
        #Check XSS attack
        if self._check_XSS_attack():
            suspicious_ip_instance.ip = self.client_address[0]
            suspicious_ip_instance.reason = "XSS attack"
            suspicious_ip_instance.save()
            return True
        #Check for header injection
        if self._check_header_injecion():
            suspicious_ip_instance.ip = self.client_address[0]
            suspicious_ip_instance.reason = "Header Injection"
            suspicious_ip_instance.save()
            return True
        #Check for body injection
        if self._check_body_injection():
            suspicious_ip_instance.ip = self.client_address[0]
            suspicious_ip_instance.reason = "Body Injection"
            suspicious_ip_instance.save()
            return True
        #Check directory traversal
        if self._check_directory_traversal():
            suspicious_ip_instance.ip = self.client_address[0]
            suspicious_ip_instance.reason = "Directory traversal"
            suspicious_ip_instance.save()
            return True
        return False
    #End url header check
    #Body check
    def _check_body_sql_injection(self,body):
        # self.sql_injection_word
        # Need to process path
        # It wil have this form WHERE%20USER%FIND%20SOMETHING
        tempt = (' '.join(body.split("%20"))).lower()
        print(tempt)
        count = 0
        for i in self.sql_injection_word:
            if tempt.find(i.lower()) != -1:
                count = count + 1
            if count >= 3:
                # Log this request to our sql_injection_attack log
                suspicious_ip_instance = Suspiciousips()
                suspicious_ip_instance.ip = self.client_address[0]
                suspicious_ip_instance.reason = "SQL injection"
                suspicious_ip_instance.save()
                return True
        return False

    def _check_body_xss_injection(self):

        return
    # After detect it let sanitize it
    def _sanitize_input(self):

        return


#TODO:
# Create rule and analyze for GET request
# Create rule and analyze for POST request
# We need different rule and different analyst technique for each individual REQUEST METHOD
# We will strongly focus on GET AND POST Request
    def do_GET(self):

        #Ingoing request from internet user
        #Code number convention:
        #(1 is allowed, 0 is not allow)
        #TODO:
        # Identify if an ip is bad or not (Scoring system)
        # Blacklist IP database from the Internet ( thinking about this)
        # Check if request is legit and then forward it to our client application
        # Use blackListIPaddr function (Done, Need to create a admin page for this, create a database for this)
        # Use Geolocation function (Done)
        # Prevent path traversal
        # Prevent malicious headers and body
        # LOG IP ADDRESS (Done, but if we want to scale, need to override this function)
        # Prevent nmap, port scanner (Done,Andrew)
        # SQlinjection (Khang)
        # Restrictive port access
        # ALERT TO SUBSCRIBER TO TAKE ACTION EITHER BY EMAIL OR PHONE (Need to create rule for this)
        # ADVANCE STUFF:
        # USE MACHINE LEARNING TO RECOGNIZE MALICIOUS ACTION
        # FIND A WAY TO OPTIMIZE OVERHEAD AND MAKE APPLICATION RUN SMOOTHLY MEANING FAST TRANSACTION TIME
        # REFERENCE: https://docs.python.org/3.4/library/http.server.html
        #We know this is GET /path

        #This is only for test
        #Analyze path
        #Analyze ip address
        #This is a function to process ip address
        #def blackListIPaddr(self.client_address)
        #This is a function to process path
        #def pathAnalyze(self.path)
        #This is a rule function which contains all the rule we want require both ipaddress,port and path
        #def allTheRule(self.client_address,self.path)
        #Implement TODO here:
        # Use blackListIPaddr function
        #Sniffing that packet first
        #if not UserBanIpAddr(self.client_address[0]):
            #return
        #Use
        #Portscanner will passively listen to incoming requests
        #if not banPortScannerIP(self.client_address[0]):
            #return
        #if not GeoLocationBanIP(self.client_address[0]):
            #return



        # Log client ipaddr, port , request method, path
        # to database for traffic monitoring and analyzing
        logfile_instance = logfile(
            ip=self.client_address[0],
            port=self.client_address[1],
            requestType=self.command,
            path=self.path
        )
        logfile_instance.save()
        #Log suspicious ip addr
        # to suspiciousips

        if self._check_suspicious_request():
            self._html_suspicious_request()
            #Log this ip address to suspicious ip address
            return

        privilege = False
        #If you have whitelist ip addr, you have privilege to bypass checking zone

        for whitelistip in Whitelistips.objects:
            print("White list ip:", whitelistip.ip)
            if self.client_address[0] == whitelistip.ip:
                privilege = True

        if not privilege:
            # Check this ip address against our black list ipadrr
            for blacklistip in Blacklistips.objects:
                if self.client_address[0] == blacklistip.ip:
                    self._html_suspicious_request()
                    return
            print("end bad ip section")
            #End check against our blacklist ip addrr

            #Drop traffic if it is illegal here
            #print(self.headers)
            #forward this request to our web client
            #Redirect customer to github.com right away
            #Redirect to url
            #Origin need to be from this IP address (White list )
            # End Drop traffic if it is illegal here

            #If traffic is legal, let it go here
        #Send traffic to our client aplication
        url = 'http://localhost:3000'
        #Find a way to not hardcoded this
        #cookies = {'logged': '5dc3385173801b38680e679c'}
        #cookies={"logged":"12345"}
        response = requests.get(url + self.path)
        if response.status_code == 404:
            self._html_not_found()
            return
        self._set_headers(response.status_code)
        #Do not let it redirect
        #Outgoing back to internet's user
        self.wfile.write(response.text.encode("utf-8"))
        #End forward request
        self.log_format(response.status_code, "")
        return

    def do_POST(self):
        #TODO:
        # Check if request is legit and then forward it to our client application
        # USe blackListIPaddr function
        # Use Geolocation function
        # Prevent path traversal
        # Prevent malicious headers and body
        # LOG IP ADDRESS
        # Prevent nmap, sql injection, port scanner
        # Restrictive port access
        # Implement a function which do not allow upload file
        # ALERT TO SUBSCRIBER TO TAKE ACTION EITHER BY EMAIL OR PHONE
        # ADVANCE STUFF:
        # USE MACHINE LEARNING TO RECOGNIZE MALICIOUS ACTION
        # FIND A WAY TO OPTIMIZE OVERHEAD AND MAKE APPLICATION RUN SMOOTHLY MEANING FAST TRANSACTION TIME
        # REFERENCE: https://docs.python.org/3.4/library/http.server.html

        #Ingoing request from internet user
        #Log to database for traffic monitoring
        header = logfile(
            ip=self.client_address[0],
            port=self.client_address[1],
            requestType=self.command,
            path=self.path
        )
        header.save()

        #Check url request
        if self._check_suspicious_request():
            self._html_suspicious_request()
            # Log this ip address to suspicious ip address
            return

        content_len = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_len).decode("utf-8")
        #Convert this to json and send to github for authentication
        #Check for SQL injection

        post_body = unquote(post_body) #url decoded
        #Check sql injection and XSS
        body = post_body

        #Body sql injection

        if self._check_body_sql_injection(body) or self._check_body_XSS_attack(body):
            self._html_suspicious_request()
            return
        if self._check_body_XSS_attack(body):
            suspicious_ip_instance = Suspiciousips()
            suspicious_ip_instance.ip = self.client_address[0]
            suspicious_ip_instance.reason = "XSS ATTACK"
            suspicious_ip_instance.save()
            return
        post_body = post_body.split("&")
        data = dict()

        for i in post_body:
            i = i.split("=")
            if len(i) == 1:
                i.append('')
            if len(i[1]) >= 345: #Submited string is more than 345
                continue
            #Check i[1] here
            data.update({i[0]: i[1]})

        #Change this url to web client application
        url = 'http://localhost:3000'

        response = requests.post(url + self.path, data=data)

        self._set_headers(response.status_code)
        self.wfile.write(response.text.encode("utf-8"))
        self.log_format(response.status_code, body)

        return


def run(server_class=HTTPServer, handler_class=S):
    #Ok server is running fine
    #Need to handle GET request first
    #Then forward this request to our web  client
    current_addr = socket.gethostbyname(socket.gethostname())
    port = 50000
    print(current_addr)
    server_address = (current_addr, port)
    httpd = server_class(server_address, handler_class)
    print("Server is running on port {0}".format(port))

    #Run web server here
    #

    httpd.serve_forever()

if __name__ == "__main__":
    #buffer = 1
    #They will build more sophisticated log file
    #sys.stderr = open('var/log/event.txt', 'w', buffer)
    # python app.py -url=
    run()
