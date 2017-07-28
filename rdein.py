import socket
import os
import fcntl
import struct
from scapy.all import *

#hostAtivos = []
hostsFTP = []
versoes = []
hostsSMTP = []
hostsSSH = []

def enumRedes(nome_rede, range_rede_um=None, range_rede_dois=None):
    nsSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip_addr = socket.inet_ntoa(fcntl.ioctl(nsSocket.fileno(), 0x8915, struct.pack('256s', nome_rede[:15]))[20:24])
    print "Your ip: "+ip_addr
    ips = []
    for i in str(ip_addr).split("."):
        ips.append(i)
    try:
        
        if range_rede_um == False:
            range_rede_um = 1
        if range_rede_dois == False:
            range_rede_dois = 255

        for i in range(int(range_rede_um), int(range_rede_dois)):
            ip = "%s.%s.%s.%s"%(ips[0], ips[1], ips[2], str(i))
            if ip == "0.0.0.0":
                pass
            else:
                newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if newSocket.connect_ex((ip, 21)) == 0:
                    #hostAtivos.append(ip)
                    hostsFTP.append(ip)
                    #print "\033[01;32m[+] %s - ftp up\033[01;37m"%(ip)
                    otherSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if otherSocket.connect_ex((ip, 25)) == 0:
                        #print "\033[01;32m[+] %s - ftp up and smtp up\033[01;37m"%(ip)
                        hostsSMTP.append(ip)   
                        otherSocket.close()
                        MoreSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if MoreSocket.connect_ex((ip, 22)) == 0:
                            hostsSSH.append(ip)
                            MoreSocket.close()
                            otherSocket.close()
                            print "\033[01;32m[+] %s - ftp up | smtp up | ssh up\033[01;37m"%(ip)
                        else:
                            MoreSocket.close()
                            otherSocket.close()
                            print "\033[01;32m[#] %s - ftp up | smtp up |\033[01;37m\033[01;31m ssh down\033[01;37m"%(ip)
                    else:
                        MoreSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if MoreSocket.connect_ex((ip, 22)) == 0:
                            hostsSSH.append(ip)
                            MoreSocket.close()
                            otherSocket.close()
                            print "\033[01;32m[#] %s - ftp up \033[01;37m\033[01;31m | smtp down |\033[01;37m\033[01;32m ssh up\033[01;37m"%(ip)
                        else:

                            print "\033[01;32m[#] %s - ftp up \033[01;37m\033[01;31m | smtp down | ssh down\033[01;37m"%(ip)
                            otherSocket.close()

                else:
                    otherSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    if otherSocket.connect_ex((ip, 25)) == 0:
                        print "\033[01;31m[#] %s - ftp down\033[01;37m\033[01;32m and smt up\033[01;37m"%(ip)
                        hostsSMTP.append(ip)
                        otherSocket.close()
                        MoreSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if MoreSocket.connect_ex((ip, 22)) == 0:
                            hostsSSH.append(ip)
                            MoreSocket.close()
                            print "[#] %s - ftp down | smtp up | ssh up"%(ip)
                        else:
                            print "[#] %s - ftp down | smtp up | ssh down"%(ip)
                            MoreSocket.close()
                    else:
                        #print "\033[01;31m[#] %s - ftp down and smtp down\033[01;37m"%(ip)
                        otherSocket.close()
                        MoreSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        if MoreSocket.connect_ex((ip, 22)) == 0:
                            hostsSSH.append(ip)
                            MoreSocket.close()
                            print "[#] %s - ftp down | smtp down | ssh up"%(ip)
                        else:
                            MoreSocket.close()
                            print "[!] %s - ftp down | smtp down | ssh down"%(ip)
                newSocket.close()
    except:
        print "Erro"


def capture(pacote):
    if pacote[TCP].payload:
        mail_pacote = str(pacote[TCP].payload)
        if "user" in mail_pacote.lower() or "pass" in mail_pacote.lower():
            print "[+] Server: %s"%(pacote[IP].dst)
            print "[+] %s"%(pacote[TCP].payload)



def Active():
    print "+---------------ACTIVE---------------+"
    for host in hostsFTP:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, 21))
            rcves = s.recv(1024)
            print "\033[01;32m[!] Host: %s FTP ===> %s\033[01;37m"%(host, rcves)
            s.close()
            versoes.append(rcves)
        except:
            print "\033[01;31m[-] Connection refused\033[01;37m"
    for host in hostsSMTP:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, 25))
            rcves = s.recv(1024)
            print "\033[01;32m[!] Host: %s SMTP ===> %s\033[01;37m"%(host, rcves)
            s.close()
            versoes.append(rcves)
        except:
            print "\033[01;31m[-]Connection Refused\033[01;37m"
    for host in hostsSSH:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((host, 22))
            rcves = s.recv(1024)
            print "\033[01;32m[!] Host: %s SSH ===> %s\033[01;37m"%(host, rcves)
            s.close()
            versoes.append(rcves)
        except:
            print "\033[01;31m[-]Connection Refused\033[01;37m"
#enumRedes()
#Active()
