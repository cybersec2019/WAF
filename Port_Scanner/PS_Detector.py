import socket
import time
import threading
from .HashTable import HashTable
from .PacketFormatter import PacketFormatter

pf = PacketFormatter()
hs = HashTable()
stop_threads = False
keyList = []
fanOutRateDict = {}
threatDict = {}
averageFanoutDict = {}

def PS_Detector():
	snifferThread = threading.Thread(name='sniffer', target=sniffer)
	deleteThread = threading.Thread(name='deleteOldRecords', target=deleteOldRecords)
	printAverageThread = threading.Thread(name='printAverage', target=printAverage)
	snifferThread.start()
	deleteThread.start()
	printAverageThread.start()
	print("running...")
	
	while True:
		userInput = input("Type 'quit' to stop Port Scanner Detector.")
		if userInput == "quit":
			stop_threads = True
			break

	snifferThread.join()
	deleteThread.join()
	printAverageThread.join()
	
def sniffer():

    while stop_threads == False:
        packets = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

        ethernet_data, address = packets.recvfrom(65536)
        dest_mac, src_mac, protocol, ip_data = pf.ethernet_dissect(ethernet_data)
        if protocol == 8:
            ip_protocol, src_ip, dest_ip, transport_data = pf.ipv4_dissect(ip_data)
            if ip_protocol == 6:
                src_port, dest_port = pf.tcp_dissect(transport_data)
                recordConnection(src_ip, dest_ip, dest_port)

# either adds to hash table, or increments the fanOut count
def recordConnection(src_ip, dest_ip, dest_port):
    if hs.find([src_ip, dest_ip]):
        #print("Record already in dictionary")
        incrementFanOutDict(src_ip, dest_ip, time.time())
    else:
        hs.insert([src_ip, dest_ip], [dest_port, time.time()])
        keyList.append([src_ip, dest_ip])
        #print("Record added successfully")


def incrementFanOutDict(src_ip, dest_ip, ts):
    if fanOutRateDict.get(src_ip):
        destinationDict = fanOutRateDict.get(src_ip)
        if destinationDict.get(dest_ip):
            calculateFanOut(src_ip, dest_ip)
        else:
            destinationDict[dest_ip] = [ts, 0, 0, ts, 0, 0, ts, 0]

    else:
        destinationDict = {}
        destinationDict[dest_ip] = [ts, 0, 0, ts, 0, 0, ts, 0]
        fanOutRateDict[src_ip] = destinationDict

def calculateFanOut(src_ip, dest_ip):
    if src_ip in fanOutRateDict.keys():
        destinationDict = fanOutRateDict.get(src_ip)
        if dest_ip in destinationDict.keys():
            value = destinationDict.get(dest_ip)

            if time.time() - value[0] < 1:
                value[1] += 1
            else:
                value[0] = time.time()
                value[2] = (value[1] + value[2])/2
                value[1] = 0

            if time.time() - value[3] < 59:
                value[4] += 1
            else:
                value[3] = time.time()
                value[5] = (value[4] + value[5])/2
                value[4] = 0

            if time.time() - value[6] < 299:
                value[7] += 1
            destinationDict[dest_ip] = value
            fanOutRateDict[src_ip] = destinationDict

        if time.time() - value[6] > 300:
            calculateAverageFanoutRate(src_ip, dest_ip, value)
            del(destinationDict[dest_ip])
            fanOutRateDict[src_ip] = destinationDict


def calculateAverageFanoutRate(src_ip, dest_ip, value):
    if src_ip in averageFanoutDict:
        destinationDict = averageFanoutDict.get(src_ip)
        if dest_ip in destinationDict.keys():
            averageValue = destinationDict.get(dest_ip)
            if averageValue[0] == 0:
                averageValue[0] = value[2]
            else:
                averageValue[0] = (averageValue[0] + value[2])/2
            if averageValue[1] == 0:
                averageValue[1] = value[5]
            else:
                averageValue[1] = (averageValue[1] + value[5])/2
            if averageValue[2] == 0:
                averageValue[2] = value[7]
            else:
                averageValue[2] = (averageValue[2] + value[7])/2

            destinationDict[dest_ip]  = averageValue
            averageFanoutDict[src_ip] = destinationDict
        else:
            destinationDict = {}
            destinationDict[dest_ip] = [value[2], value[5], value[7]]
            averageFanoutDict[src_ip] = destinationDict
    else:
        destinationDict = {}
        destinationDict[dest_ip] = [value[2], value[5], value[7]]
        averageFanoutDict[src_ip] = destinationDict

def printAverage():
    #ts = datetime.datetime.now().timestamp()
    ts = time.time()

    while stop_threads == False:
        if time.time() - ts >= 60:
           ts = time.time()
           #print(len(averageFanoutDict.keys()))
           if len(averageFanoutDict.keys()) is 0:
               print("NO PORT SCANNERS DETECTED")
           else:
               print("UPDATED PORT SCANNERS AND AVERAGE CONNECTION ATTEMPTS:")
               for k in averageFanoutDict:
                   v = averageFanoutDict.get(k)
                   for v2 in v:
                       print("Portscanner detected on source ip ", k)
                       print(" Average fanout per sec: ", v2[0], ", per min: ", v2[1], ", per 5 min: ", v2[2], "/5m")

def deleteOldRecords():

    while stop_threads == False:
        if hs.size > 0:
            for item in keyList:
                if hs.removeOld(item) == True:
                    keyList.remove(item)
                    print("Old item deleted")
                    break

