#Importation modules générales
import time
import os
import re
import sys

#Importation module log
import logging as lg
if os.path.isfile('00_data\\log.txt'):
    os.remove('00_data\\log.txt')

lg.basicConfig(filename='00_data\\log.txt', filemode='a', format='%(asctime)s,%(msecs)d %(name)s %(levelname)s %(message)s',datefmt='%H:%M:%S',level=lg.INFO)

#Importation module
import nmap
import requests
from bs4 import BeautifulSoup
from subprocess import PIPE, run


class Nav():
    """
    Classe generant un bot pour automsatiser des tache sur internet
    """
    def __init__(self, addr):
        """
            Initialisation d'une session
        """
        lg.info("Initialisation du bot")
        self.s = requests.Session()
        self.addr = [addr]
        self.addrDone = []
        self.listeMail = []
        self.listNumber = []


    def requestGet(self):
        """
            Methode pour recuperer contenu page
        """
        lg.info("Entre dans requestGet")
        print("Recuperation du contenu de la page du navigateur")
        for elm in self.addr:
            if not elm in self.addrDone:
                try:
                    #On complete le path du driver
                    self.res = self.s.get(elm)
                    self.addrDone.append(elm)
                    lg.info("requestGet OK")
                    break
                except:
                    print("Lancement du navigateur : Erreur lors du lancement")
                    lg.warning("Erreur dans request GET")
                
    def completeListAddr(self):
        """
            Methode pour retrouver un lien en parsant du HTML
        """
        print("Recherche de liens")
        lg.info("Debut du recherche lien dans sous domaine - completeListAddr")
        soup = BeautifulSoup(self.res.text, 'html.parser')

        for a in soup.find_all('a'):
            if self.addr[0] in str(a.get('href')) and not str(a.get('href')) in self.addr:
                self.addr.append(str(a.get('href')))
                lg.info("Lien trouver avec sous domaine")
            elif str(a.get('href')).startswith('/') and str(self.addr[0]+a.get('href')) not in self.addr:
                    self.addr.append(str(self.addr[0]+a.get('href')))
                    lg.info("Lien trouver avec chemin rlatif")

    def getMailAddress(self, addr=""):
        """
            Methode pour retrouver les adresse mails sur une page
        """
        lg.info("Debut du recherche adresse mail sur la page")
        print("Recherche d'adresse mail")
        soup = BeautifulSoup(self.res.text, 'html.parser')
        
        #regex mail
        regex1 = '[a-zA-Z0-9_.+-]+\[at\]+[a-zA-Z0-9-]+\[dot\][a-zA-Z0-9-.]+'
        regex2 = '[^@]+@[^@]+\.[^@]+'
        for reg in [regex1, regex2]:
            for elm in soup.find_all(string=re.compile(reg)):
                if elm.strip() not in self.listeMail:
                    self.listeMail.append(elm.strip())

                        

    def getPhoneNumber(self, addr=""):
        """
            Methode pour retrouver les numéros de téléphone sur une page
        """
        lg.info("Debut de recherche de numéros de téléphone sur la page")
        print("Recherche de numéros de téléphone")
        soup = BeautifulSoup(self.res.text, 'html.parser')
        
        #regex phone
        regex = '(?:(?:\+|00)33|0)\s*[1-9](?:[\s.-]*\d{2}){4}'
        for reg in [regex]:
            for elm in soup.find_all(string=re.compile(reg)):
                result = re.search(regex, elm.strip()).group(0)                
                if result not in self.listNumber:
                    self.listNumber.append(result)


if __name__ == "__main__":

    #Init variables
    lg.info("Debut du programme")
    addr = 'https://serval-concept.com'
    sorti = False

    #Init nav
    nav = Nav(addr)

    #request WebPage vers premiere page
    nav.res = nav.s.get(addr)

    #on boucle sur tous les liens du domaines:
    while len(nav.addr) > len(nav.addrDone):
                
        #On cherche tout le liens de la page du domaine
        nav.completeListAddr()
        

        #On parse pour avoir les adressde mail est numero
        nav.getMailAddress()
        nav.getPhoneNumber()

        #On rejoint la page suivante
        nav.requestGet()
    print(nav.listeMail)
    print(nav.listNumber)

    #os.system("ping -c 1 -W 1 " + addr[8:] + " > file")

    command = 'ping -w 1 serval-concept.com | grep -Eo \'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\''
    result = run(command, stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
    print(result.stdout)
    nm = nmap.PortScanner()
    nm.scan(hosts=result.stdout + '/24', arguments='-n -sP -PE -PA21,23,80,3389')
    hosts_list = [(x, nm[x]['status']['state']) for x in nm.all_hosts()]
    for host, status in hosts_list:
        print('{0}:{1}'.format(host, status))
    
