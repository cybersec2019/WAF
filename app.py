from flask import Flask
from Port_Scanner.PS_Detector import PS_Detector
from blackListIP.blackListIP import *
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
from notification.mailNotification import *
import requests
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
        #TODO:
        #  Check if request is legit and then forward it to our client application
        # USe blackListIPaddr function
        # Use Geolocation function
        # Prevent path traversal
        # Prevent malicious headers and body
        # LOG IP ADDRESS
        # Prevent nmap, sql injection, port scanner
        # Restrictive port access
        # ALERT TO SUBSCRIBER TO TAKE ACTION EITHER BY EMAIL OR PHONE
        # ADVANCE STUFF:
        # USE MACHINE LEARNING TO RECOGNIZE MALICIOUS ACTION
        # FIND A WAY TO OPTIMIZE OVERHEAD AND MAKE APPLICATION RUN SMOOTHLY MEANING FAST TRANSACTION TIME
        # REFERENCE: https://docs.python.org/3.4/library/http.server.html
        #We know this is GET /path
        #print(self.path)
        #This is only for test
        #Analyze path
        #Analyze ip address
        print("Client ip:{0}".format(self.client_address))
        #This is a function to process ip address
        #def blackListIPaddr(self.client_address)
        #This is a function to process path
        #def pathAnalyze(self.path)
        #This is a rule function which contains all the rule we want require both ipaddress,port and path
        #def allTheRule(self.client_address,self.path)

        print("Here is self.path {0}".format(self.path))
        if self.path == "/This+is+suspicious+code":
            self.send_response(404)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(self._html("Dude, you messed up with the wrong engine, LynxServer"))
            return
            #Drop this traffic here
        #print(self.headers)
        #forward this request to our web client
        ip = 'https://github.com/'
        response = requests.get(ip+ self.path)
        self._set_headers()
        self.wfile.write(self._html(response.text))
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
        #  Restrictive port access
        # Implement a function which do not allow upload file
        # ALERT TO SUBSCRIBER TO TAKE ACTION EITHER BY EMAIL OR PHONE
        # ADVANCE STUFF:
        # USE MACHINE LEARNING TO RECOGNIZE MALICIOUS ACTION
        # FIND A WAY TO OPTIMIZE OVERHEAD AND MAKE APPLICATION RUN SMOOTHLY MEANING FAST TRANSACTION TIME
        # REFERENCE: https://docs.python.org/3.4/library/http.server.html
        self._set_headers()
        self.wfile.write(self._html("Still developing this!"))


def run(server_class=HTTPServer, handler_class=S):
    #Ok server is running fine
    #Need to handle GET request first
    #Then forward this request to our web  client
    server_address = ('10.134.71.185', 8000)
    httpd = server_class(server_address, handler_class)
    print("Server is running on port {0}".format("8000"))
    httpd.serve_forever()

if __name__ == "__main__":
    #mail_notification()
    # Allow traffic or drop traffic in here
    run()