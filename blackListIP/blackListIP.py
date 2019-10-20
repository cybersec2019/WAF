import geocoder
import os
dirname = os.path.dirname(__file__)
#These module uses to prevent source IP address get through our Web Application Firewall
#Return code:
# 0 is not allowed
# 1 is allowed
def GeoLocationBanIP(ipaddr):
    g = geocoder.ip(ipaddr)
    country = (g.json["country"])
    print(country)
    if country == "CN" or country == "RU" or country == "KP":
        print("These IP addr are not allowed")
        return 0
    else:
        print("These IP addr are allowed")
    return 1

def UserBanIpAddr(ipaddr):
    #Read file from user
    filepath = os.path.join(dirname, '../static/user_ban_ip_addr.txt')
    with open(filepath) as fp:
        line = 1
        while line:
            line = fp.readline()
            line = line.strip()
            if ipaddr == line:
                print("This ip is not allowed")
                #Return code should be 0
                return 0
    print("This ip is allowed")
    return 1

def banPortScannerIP(ipaddr):
    # Read file from user
    filepath = os.path.join(dirname, '../static/port_scanner_ban_ip_addr.txt')
    with open(filepath) as fp:
        line = 1
        while line:
            line = fp.readline()
            line = line.strip()
            if ipaddr == line:
                print("This ip is not allowed")
                # Return code should be 0
                return 0
    print("This ip is allowed")
    return 1