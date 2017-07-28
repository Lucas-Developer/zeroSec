import rdein
import webcr
import argparse
from scapy.all import *
def banner():
    print """ 
    \033[01;31m@@@@@@@@  @@@@@@@@  @@@@@@@    @@@@@@       @@@@@@   @@@@@@@@   @@@@@@@  
    @@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@@     @@@@@@@   @@@@@@@@  @@@@@@@@  
         @@!  @@!       @@!  @@@  @@!  @@@     !@@       @@!       !@@       
        !@!   !@!       !@!  @!@  !@!  @!@     !@!       !@!       !@!       
       @!!    @!!!:!    @!@!!@!   @!@  !@!     !!@@!!    @!!!:!    !@!       
      !!!     !!!!!:    !!@!@!    !@!  !!!      !!@!!!   !!!!!:    !!!       
     !!:      !!:       !!: :!!   !!:  !!!          !:!  !!:       :!!       
    :!:       :!:       :!:  !:!  :!:  !:!         !:!   :!:       :!:       
     :: ::::   :: ::::  ::   :::  ::::: ::     :::: ::    :: ::::   ::: :::  
    : :: : :  : :: ::    :   : :   : :  :      :: : :    : :: ::    :: :: : 
    \033[01;37m
    """


def argumentosModo():
    global args
    
    parser = argparse.ArgumentParser()
    
    parser.add_argument("-m", dest="modo", help="define o modo de uso", required=True)
    parser.add_argument("-url", dest="url", help="Define a url do site que sera enumerado", required=False)
    parser.add_argument("-wordlist", dest="lista", help="Define uma wordlist", required=False)
    parser.add_argument("-snif", dest="snifar", help="Snifa sua rede a procura de credenciais de emails", required=False)
    parser.add_argument("-dns", dest="dns", help="Define se ira fazer enumeracao de dns", required=False)
    parser.add_argument("-i", dest="nome_rede", help="Define o nome de sua rede", required=False)
    parser.add_argument("-r1", dest="range_um", help="Define onde ira comecar a enumeracao da rede", required=False)
    parser.add_argument("-r2", dest="range_dois", help="Define o final da rede", required=False)
    parser.add_argument("-sr", dest="find_xpl", help="procura exploit para a versao do servico", required=False) #em desenvolvimento
    
    args = parser.parse_args()

def capture(pacote):
    if pacote[TCP].payload:
        mail_pacote = str(pacote[TCP].payload)
        if "user" in mail_pacote.lower() or "pass" in mail_pacote.lower():
            print "\033[01;32m[+] Server: %s\033[01;37m"%(pacote[IP].dst)
            print "\033[01;32m[+] %s\033[01;37m"%(pacote[TCP].payload)

def main():
    banner()
    argumentosModo()
    if args.modo == "lan":
        
        if args.nome_rede:
            
            if args.range_um != "" and args.range_dois != "":
            
                rdein.enumRedes(args.nome_rede, args.range_um, args.range_dois)
                rdein.Active()
            
            elif args.range_um != "" and args.range_dois == "":
            
                rdein.enumRedes(args.nome_rede, args.rede_um, 255)
                rdein.Active()
            
            elif args.range_um == "" and args.range_dois == "":
                
                rdein.enumRedes(args.nome_rede, 1, args.range_dois)
                rdein.Active()
            
            else:
                exit()
        elif args.snifar == "true":
            try:
                sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=capture, store=0)
            except:
                print "\033[01;31m[!] This module required root privileges\033[01;37m"
    
    elif args.modo == "wan":

        if args.url != "":
            if args.dns == "True":
            
                webcr.SearchRange(args.url)
    else:

        print "\033[01;31m[!] Esse modo nao existe\033[01;37m"
        exit()

main()
