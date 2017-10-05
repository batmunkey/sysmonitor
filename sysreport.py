#!/usr/bin/python
###
# Create a sysreport for and email the results.
###
__version__ ='1.2'
__author__ ='Sam Powell'
__date__ ='3/20/17'
__org__ ='batmunkey'

import urllib2
import re
import sys
import os
import logging
import ConfigParser
import os.path
import smtplib
import subprocess
import time

try:
    import paramiko
except (IOError, MemoryError, OSError, SyntaxError):
    print "Please run pip install paramiko"

from datetime import date, tzinfo, timedelta, datetime
from email import encoders
from email.message import Message
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

### Bring in the conf file for SSH
parser = ConfigParser.ConfigParser()
parser.read('./sshInfo.conf')

# Build a logger
def instantiateLogger():
    global logger
    logger = logging.getLogger("sysreport")
    hdlr = logging.FileHandler("/var/log/sysreport.log")
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.INFO)

# Add python system statistics to log file
def pythonSystemStats():
    versionpy = subprocess.check_output("python --version", stderr=subprocess.STDOUT, shell=True)
    whichpy = subprocess.check_output("which python", shell=True)
    osslpy = subprocess.check_output("python -c 'import ssl; print ssl.OPENSSL_VERSION'", shell=True)
    logger.info("Your version of python is " + versionpy.rstrip("\n"))
    logger.info("Here is the path to your python " + whichpy.rstrip("\n"))
    logger.info("This is your pythons openssl version " + osslpy.rstrip("\n"))

def setTime():
    global timeStamp
    t = datetime.now()
    rawtime = str(t)
    timeStamp = rawtime.replace(" ", "")

def sshGetCreds(device):
    global dev
    global uname
    global ip
    dev = device
    uname = parser.get(device, "USER")
    ip = parser.get(device, "IP")

# Use ssh keys not password, edit port if needed
def sshLogin(ip, uname):
    global client
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=22, username=uname, look_for_keys=True)
    connection = client.invoke_shell()

def runCommands():
    global location
    outdata, errdata = '', ''
    ### Set default file repo location here
    location = ""

    try:
        stdin, stdout, stderr = client.exec_command("touch " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The command touch " + location + timeStamp + "-status.txt failed")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo ------- Server Report ------- >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The echo title command failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("date >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The date command ------- Server Report ----- failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo ------- Output of df -h ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("df -h >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The command df -h failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo ------- Output of du -sh ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("du -sh /etc /home /var/log /var/www /tmp >> " + location + timeStamp + "-status.txt" + "\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("du -sh finished")
        else:
            logger.error("du -sh failed") 
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The command du -sh failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    ### Scans /home /var/www and /etc by default
    try:
        # Restart clam and update virus db's
        stdin, stdout, stderr = client.exec_command("echo ------- Clamav Output ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("sudo systemctl stop clamav-freshclam >> " + location + timeStamp + "-status.txt\n")
        time.sleep(2)
        stdin, stdout, stderr = client.exec_command("sudo freshclam -v >> " + location + timeStamp + "-status.txt\n")
        time.sleep(2)
        stdin, stdout, stderr = client.exec_command("sudo systemctl start clamav-freshclam >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
        # Scan the important directories
        stdin, stdout, stderr = client.exec_command("sudo clamscan -r -i /home/wiki >> " + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("clamscan -r -i /home finished")
        else:
            logger.error("clamscan -r -i /home failed")
        stdin, stdout, stderr = client.exec_command("sudo clamscan -r -i /etc >> " + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("clamscan -r -i /etc finished")
        else:
            logger.error("clamscan -r -i /etc failed")
        time.sleep(1)
        stdin, stdout, stderr = client.exec_command("sudo clamscan -r -i /var/www >> " + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("clamscan -r -i /var/www finished")
        else:
            logger.error("clamscan -r -i /var/www failed")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The freshclam block of commands failed")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit() 

    # Internet specs
    try:
        stdin, stdout, stderr = client.exec_command("echo ------- Output of ifconfig ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("ifconfig ens33 >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The ifconfig command failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo ------- Output of netstat ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("netstat -an | more | grep LISTEN | grep -v LISTENING >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The ifconfig command failed")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    # Scan the network with nmap, change the network accordingly
    try:
        stdin, stdout, stderr = client.exec_command("echo ------- nmap output ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("nmap -Pn localhost >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
        stdin, stdout, stderr = client.exec_command("nmap -sP 192.168.0.0/24 >> " + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("nmap -sP of the local network finished")
        else:
            logger.error("nmap -sP of the local network failed")
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    # Check for rootkits
    try:
        stdin, stdout, stderr = client.exec_command("echo ------- Root Kit Hunter Results ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("sudo /usr/bin/rkhunter --syslog --check --skip-keypress &>> " + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("/usr/bin/rkhunter --syslog --check --skip-keypress finished")
        else:
            logger.error("/usr/bin/rkhunter --syslog --check --skip-keypress failed")
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("echo ------- Check Root Kit Results ------- >> " + location + timeStamp + "-status.txt\n")
        stdin, stdout, stderr = client.exec_command("sudo /usr/sbin/chkrootkit &>> " + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("chkrootkit finished")
        else:
            logger.error("chkrootkit failed")
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The the rootkitcheck failed")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit() 

    # Redownload block lists for bind and reload the service
    try:
        stdin, stdout, stderr = client.exec_command("sudo rm /etc/namedb/blackhole/spywaredomains.zones.bck\n")
        time.sleep(1)
        stdin, stdout, stderr = client.exec_command("sudo mv /etc/namedb/blackhole/spywaredomains.zones /etc/namedb/blackhole/spywaredomains.zones.bck\n")
        time.sleep(1)
        stdin, stdout, stderr = client.exec_command("sudo wget http://mirror1.malwaredomains.com/files/spywaredomains.zones -P /etc/namedb/blackhole/\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            stdin, stdout, stderr = client.exec_command("sudo mv  /etc/namedb/blackhole/spywaredomains.zones.bck /etc/namedb/blackhole/spywaredomains.zones\n")
            logger.error("Failed to download the new spyware block lists, reverting to backup...")
        elif exit_status == 0:
            logger.info("Successfully downloaded the new spyware blocklists")
        else:
            logger.error("Failed to download the new spyware blocklist to bind9, also failed to revert to backup")
        time.sleep(1)
        stdin, stdout, stderr = client.exec_command("sudo systemctl reload bind9\n")
        time.sleep(1)
        stdin, stdout, stderr = client.exec_command("sudo systemctl status bind9 >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The BIND9 block of commands failed")
        stdin, stdout, stderr = client.exec_command("rm " + location + timeStamp + "-status.txt\n")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    # Run AIDE 
    try:
        stdin, stdout, stderr = client.exec_command("sudo /usr/bin/aide.wrapper -c /etc/aide/aide.conf --check &>> " \
                              + location + timeStamp + "-status.txt\n")
        logger.info("Successfully completed the AIDE scan")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("AIDE failed to run")
        closeSession()
        sys.exit() 

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    # Run the block country script per https://www.countryipblocks.net/country_selection.php
    try:
        stdin, stdout, stderr = client.exec_command("/bin/sh /etc/block-country-ips.sh\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("The block country script ran successfully")
        else:
            logger.error("The block country script failed")
        stdin, stdout, stderr = client.exec_command("sudo iptables -L  >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The block country script failed")
        closeSession()
        sys.exit()

    try:
        stdin, stdout, stderr = client.exec_command("echo '\n' >> " + location + timeStamp + "-status.txt\n")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The newline command failed")
        closeSession()
        sys.exit()

    # Sync with the git server
    try:
        stdin, stdout, stderr = client.exec_command("sudo /usr/bin/git commit -a -m \"Automated commit of git changes\" &>> " \
                              + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("git commit was successful")
        else:
            logger.error("git commit failed")
        stdin, stdout, stderr = client.exec_command("sudo /usr/bin/git push -u origin master &>> " \
                              + location + timeStamp + "-status.txt\n")
        exit_status = stdout.channel.recv_exit_status()
        if exit_status == 0:
            logger.info("git push was successful")
        else:
            logger.error("git push failed")
        time.sleep(1)
    except (IOError, MemoryError, OSError, SyntaxError):
        logger.error("The git commands failed")
        closeSession()
        sys.exit()

### Add the sender and receiver email below
def sendEmail():
    COMMASPACE = ', '

    file = location + timeStamp + "-status.txt"

    # Create the container (outer) email message.
    msg = MIMEMultipart()
    msg['Subject'] = "Sysreport"
    me = ""
    receiver = ""
    msg['From'] = me
    msg['To'] = receiver 
    ### For multi-user
    #msg['To'] = COMMASPACE.join(receiver)
    msg.preamble = " Server System Report"

    # Get the file
    fp = open(file, 'rb')
    textfile = MIMEText(fp.read())
    fp.close()
    msg.attach(textfile)

    # Send the email via gmail
    mailserver = smtplib.SMTP("smtp.gmail.com",587)
    # identify ourselves to smtp gmail client
    mailserver.ehlo()
    # secure our email with tls encryption
    mailserver.starttls()
    # re-identify ourselves as an encrypted connection
    mailserver.ehlo()
    mailserver.login(parser.get("SMTP", "EMAIL"), parser.get("SMTP", "PASS"))
    mailserver.sendmail(me, receiver, msg.as_string())
    mailserver.quit()

def closeSession():
    client.close()

# Layout the main logic
def main():
    setTime()
    instantiateLogger()
    pythonSystemStats()
    sshGetCreds("")
    sshLogin(ip, uname)
    runCommands()
    sendEmail()
    closeSession()

# Run everything
if __name__ == '__main__':
    main()
