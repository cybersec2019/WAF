from flask import Flask
from Port_Scanner.PS_Detector import PS_Detector
from blackListIP.blackListIP import *
from notification.mailNotification import *
app = Flask(__name__)


if __name__ == "__main__":
    mail_notification()
    # Allow traffic or drop traffic in here