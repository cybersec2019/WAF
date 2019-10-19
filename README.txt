<h1>Project goal</h1>:
<p>
Basic functionality:
- Our WAF will intercept the http(s) calls, extract requests / response body,
analyze them, and act accordingly (drop/report/forward).
- Detect blacklist ip addresses
- Detect suspicious ip addresses (addresses making many requests in a short
period of time)
- Detect nmap, sqlmap
- Geolocation detection(Blacklist ip address, etc: North Korea, China,..)
Advance features:
- Logging
- Building GUI-based web interface for keyword search and monitoring.
- Send phone/email notifications
- Improve WAF performance (reduce network latency)
 - Auto learning new suspicious requests
Folder structure:
-App.py
Running our backend server
-Test.py
Unit test
</p>
