import requests
import socket
import rdein
import time
def GoWords(site):
	try:
		names = socket.gethostbyname(site)
		print "[+] website ip %s"%(names)
		ips = []
		for i in names.split("."):
			ips.append(i)
		for e in range(1, 30):
			ip = "%s.%s.%s.%s"%(ips[0], ips[1], ips[2], str(e))
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip, ))
			print "[+] ip %s"%(ip)
	except:
		print "[!] Error in Connection"


def SearchRange(site):
	if site[:5] == "https":
		try:
			stat = requests.get(site)
		except:
			print "\033[01;31m[!] Error in url\033[01;37m"
			exit()
		if stat.status_code == 200:
			print "[+] The website is up"
			website = site[8:]
			#print website.replace("/", "")
			#if searchDns == True:
			SearchDns(website, lista=None)
			#else:
				#GoWords(website.replace("/", ""))

		else:
			print "\033[01;31m[!] The website is down\033[01;37m"
	
	elif site[:4] == "http":
		try:
			stat = requests.get(site)
		except:
			print "\033[01;31m[!] Error in url\033[01;37m"
			exit()
		if stat.status_code == 200:
			print "[+] The website is up"
			website = site[7:]
			#print website.replace("/", "")
			#if searchDns ==True:
			SearchDns(website, lista=None)
			#else:
			#	GoWords(website.replace("/", ""))
		else:
			print "\033[01;31m[!] The website is down\033[01;37m"
	else:
		try:
			urlIp = socket.gethostbyname(site)
		except:
			print "\033[01;31m[!] Error in url\033[01;37m"
			exit()
		print "[+] Website is up"
		if urlIp != "":
			SearchDns(site, lista=None)
		else:
			print "[!] Website is down"
Ativos = []
topPorts = [21, 22, 25, 80, 110, 443, 53, 8080, 9050, 2000, 2222]
dnsAtivos = []
def SearchDns(site, lista=None):

	if site[:3] == "www":
		site = site[4:].replace("/", "")
	site.replace("/", "")
	print site
	if lista == True:
		wordlist = open(lista, "r")
	else:
		wordlist = open("wordlist/dnsSearch.lst", "r")
	
	try:
		offlist = []
		for es in wordlist.readlines():
			offlist.append(es.replace("\n", ""))
		
		for fs in offlist:
			try:
				ip_website = socket.gethostbyname(fs+"."+site.replace("/", ""))
			except:
				pass
			print "\033[01;32m[+] DNS %s.%s ====> %s\033[01;37m"%(fs,site,ip_website.replace("/", ""))
			Ativos.append(ip_website)
			dnsAtivos.append(fs+"."+site.replace("/", ""))
	except Exception as e:
		print e
	print "[?] You can go to testing the services?[y/n]"
	continuar = raw_input("zeroSec~>")
	if continuar == "y":
		for host in dnsAtivos:
			print host
			if host[:3] == "ftp":
				s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				domains = socket.gethostbyname(host)
				print domains
				if s.connect_ex((domains, 21)) == 0:
					newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
					newSocket.connect((host, 21))
					service = newSocket.recv(1024)
				else:
					pass
			else:
				pass
