from flask import Flask
from blackListIP.blackListIP import *
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import sys
import logging
from notification.mailNotification import *
import webbrowser
import requests
import simplejson
from urllib.parse import unquote
import socket
import logging
app = Flask(__name__)

#TODO:
# YOU CAN USE CURL OR BURP OR ANY SOFTWARE THAT SUITE YOU TO TEST WAF
#Handle GET , HEAD , POST request
#
class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def _html(self, message):
        """This just generates an HTML document that includes `message`
        in the body. Override, or re-write this do do more interesting stuff.
        """
        content = f"<html><body><h1>{message}</h1></body></html>"
        return content.encode("utf8")  # NOTE: must return a bytes object!
#TODO:
# Create rule and analyze for GET request
# Create rule and analyze for POST request
# We need different rule and different analyst technique for each individual REQUEST METHOD
# We will strongly focus on GET AND POST Request
    def do_GET(self):

        #Code number convention:
        #(1 is allowed, 0 is not allow)
        #TODO:
        # Identify if an ip is bad or not (Scoring system)
        #
        # Blacklist IP database from the Internet
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
        #print(self.path)
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

        #Port_Scanner

        #Process malicious path
        #This is one of the example, I need a way to make it general
        if self.path == "/This+is+suspicious+code":
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self._html("Dude, you messed up with the wrong engine, LynxServer"))
            return
            #Drop this traffic here
        #print(self.headers)
        #forward this request to our web client
        #Redirect customer to github.com right away
        #Redirect to url
        #Origin need to be from this IP address (White list )

        url = 'http://localhost:3000'
        response = requests.get(url + self.path)
        print(response.url)
        self._set_headers()
        self.wfile.write(response.text.encode("utf-8"))

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

        # Port_Scanner
        content_len = int(self.headers.get('Content-Length'))
        post_body = self.rfile.read(content_len).decode("utf-8")
        #Convert this to json and send to github for authentication
        #Check for SQL injection
        logging.basicConfig(filename='sqlinjection.log', level=logging.DEBUG)
        logging.debug(post_body)

        post_body = unquote(post_body) #url decoded
        post_body = post_body.split("&")
        data = dict()
        for i in post_body:
            i = i.split("=")
            if len(i) == 1:
                i.append('')
            if len(i[1]) >= 345:
                continue
            data.update({i[0]: i[1]})

        url = 'http://localhost:3000'
        response = requests.post(url + self.path, data=data)

        self._set_headers()
        self.wfile.write(response.text.encode("utf-8"))
        #Get form data
        #Send this form data to github
        #Whatever order, I will be able to send this data to github
        #And github will receive this data and response a nice file


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
    httpd.serve_forever()

if __name__ == "__main__":
    #buffer = 1
    #They will build more sophisticated log file
    #sys.stderr = open('var/log/event.txt', 'w', buffer)
    #
    run()