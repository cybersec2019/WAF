import os
import socket
import time
import threading
from Port_Scanner.HashTable import HashTable


hs = HashTable()
keyList = []
blacklist = {}
fanOutRateDict = {}


def PS_Detector(ip):
    deleteThread = threading.Thread(name='deleteOldRecords', target=deleteOldRecords)
    printAverageThread = threading.Thread(name='printAverage', target=printAverage)
    recordConnectionThread = threading.Thread(name='recordConnection', target= recordConnection,args=(ip,))
    deleteThread.start()
    printAverageThread.start()
    recordConnectionThread.start()
    print("running...")


# deleteThread.join()
# printAverageThread.join()

# either adds to hash table, or increments the fanOut count
def recordConnection(src_ip):
    while True:
        if hs.find(src_ip):
            # print("Record already in dictionary")
            incrementFanOutDict(src_ip, time.time())
        else:
            hs.insert(src_ip, time.time())
            keyList.append(src_ip)
            # print("Record added successfully")


def incrementFanOutDict(src_ip, ts):
    if fanOutRateDict.get(src_ip):
        calculateFanOut(src_ip)
    else:
        # this dictionary is the timestamp, total hits in the last second, and then the running average of hits per second. The the same thing for hits per minute, and hits per five minutes.
        fanOutRateDict[src_ip] = [ts, 0, 0, ts, 0, 0, ts, 0]


def calculateFanOut(src_ip):
    if src_ip in fanOutRateDict.keys():
        value = fanOutRateDict.get(src_ip)
        if time.time() - value[0] < 1:
            value[1] += 1
        else:
            value[0] = time.time()
            value[2] = (value[1] + value[2]) / 2
            value[1] = 0

        if time.time() - value[3] < 59:
            value[4] += 1
        else:
            value[3] = time.time()
            value[5] = (value[4] + value[5]) / 2
            value[4] = 0

        if time.time() - value[6] < 299:
            value[7] += 1
            fanOutRateDict[src_ip] = value


def printAverage():
    ts = time.time()

    while True:
        if time.time() - ts >= 60:
            ts = time.time()
            for ip in fanOutRateDict:
                if testFanout(ip):
                    v = fanOutRateDict.get(ip)
                    print("Portscanner detected on source ip ", ip)
                    print(" Average fanout per sec: ", v[2], ", per min: ", v[5], ", per 5 min: ", v[7])


def testFanout(ip):
    v = fanOutRateDict.get(ip)

    if v[2] > 5:
        addBlacklistIP(ip, v)
        return True
    if v[5] > 100:
        addBlacklistIP(ip, v)
        return True
    if v[7] > 300:
        addBlacklistIP(ip, v)
        return True
    return False


def addBlacklistIP(ip, v):
    blacklist[ip] = v


def testIP(ipaddress):
    if ipaddress in blacklist:
        return True
    else:
        return False


def deleteOldRecords():
    while True:
        if hs.size > 0:
            for item in keyList:
                if hs.removeOld(item) == True:
                    keyList.remove(item)
                    print("Old item deleted")
                    break