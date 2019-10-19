from flask import Flask
from Port_Scanner.PS_Detector import PS_Detector
app = Flask(__name__)


if __name__ == "__main__":
    PS_Detector()
    # app.run()
