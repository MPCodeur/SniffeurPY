#on importe toutes les méthodes de la librairy 'scapy'
from scapy.all import *

#on demande quel adresse IP doit être sniff en stockant ça dans ip_source
ip_source = input("Quel est l'IP à surveiller ?\n")

#création de la function DNS_sniff
def DNS_sniff(packets):

    #vérification que l'adresse IP du packet récupéré est la même que l'IP stocké dans ip_source
    if (str(packets[IP].src)) == (str(ip_source)):
        #si c'est le cas et que le packet a un layer DNS et que la variable qr est égal à 0
        #ce qui voudrai dire que le packet est un DNS query et non un DNS ans
        if packets.haslayer(DNS) and packets.getlayer(DNS).qr == 0:
            #on affiche le résultat tout en décriptant dans un language compréhensible (utf-8) 
            print ("requête DNS vers: " + (packets.getlayer(DNS).qd.qname).decode('utf-8'))


#on lance donc la commande sniff sur le port 53 pour s'assure d'avoir un maximum de packet DNS
#et on lui rentre notre fonction DNS_sniff qui s'éxecutera à chaque packet sniffé
sniff(filter = "port 53", prn = DNS_sniff)
