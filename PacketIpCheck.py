#on importe toutes les méthodes de la librairy scapy ainsi que les méthode de la librairy os pour utiliser les fonctions système
from scapy.all import *
import os

#on demande quel adresse IP doit être sniff en stockant ça dans ip_source
ip_source = input("Quel est l'IP à surveiller ?\n")

#création de la function IP_sniff
def IP_sniff(packets):
    #vérification si le packet à un layer IP
    if packets.haslayer(IP):
        #vérification que l'adresse IP du packet récupéré est la même que l'IP stocké dans ip_source 
        if (str(packets[IP].src)) == (str(ip_source)):
            print("IP source trouvé")
            #On demande si l'utilisateur veut afficher le packet ou simplement quitter
            PackCheck = input("Voulez-vous afficher le packet ou quitter ? (Y/Q) ")
            #si ce qu'il à entrer est Y alors on clear le terminal pour une meilleur visibilité et on affiche le packet
            if str(PackCheck) == 'Y':
                os.system('clear')
                packets.show()
            #sinon on quitte le programme tout simplement
            elif str(PackCheck) == 'Q':
                exit()
#on éxecute la fonction sniff en lui donnant notre fonction IP_sniff pour que IP_sniff sois éxecuter à chaque packet sniff
sniff(prn = IP_sniff)
