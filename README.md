# scan_all
Pythin script for indoor/outdoor scanning.

**Usage:**

sudo python3 scan_all.py
sudo python3 scan_all.py wlan1 -e

By default, the script uses wlan1, but other interfaces can be specified in the command arguemnts.
By default, the script will perform an internal scan, but this can be changed with -i or -e (for external).

The output contionuously logs to terminal: 
captureTime,srcMac,dstMac,SSID,privacy,cipher,auth,gpsLat,gpsLong,
strength,contentLength,typeExternal,typeInternal,srcIP,dstIP,
srcPort,dstPort,sniffType



**DEPENDANCIES:**

sudo apt update
sudo apt install -y aircrack-ng gpsd gpsd-clients python3-gps python3-scapy

(if pip)
pip install scapy gps python-gps



**GPS SETUP**

F-Droid GPS Forwarder app for android:
https://f-droid.org/F-Droid.apk
input raspi IP and desired port

sudo systemctl stop gpsd
sudo systemctl stop gpsd.socket
gpsd -N udp://<ur ip>:<port>

**TO MAKE PERMANENT**

sudo nano /etc/default/gpsd
comment out the DEVICES line and add:
DEVICES="udp://<ip>:<port>"
sudo systemctl start gpsd
sudo systemctl start gpsd.socket

