#on importe toutes les méthodes de la librairy scapy ainsi que les méthode de la librairy os pour utiliser les fonctions système
from scapy.all import *
import os

from sys import argv

#on demande quel adresse IP doit être sniff en stockant ça dans ip_source
#ip_source = input("Quel est l'IP à surveiller ?\n")

ip_source = sys.argv[1]

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

        elif (str(packets[IP].dst)) == (str(ip_source)):
            print("IP destination trouvé")
            PacketCheck = input("Voulez vous afficher le packet ou quitter ? (Y/Q)")
            if str(PacketCheck) == 'Y':
                os.system('clear')
                packets.show()
            elif str(PacketCheck) == 'Q':
                exit()
        else:
            print("Wrong input, please enter an IP adresse source or destination")
            exit(0)

#on éxecute la fonction sniff en lui donnant notre fonction IP_sniff pour que IP_sniff sois éxecuter à chaque packet sniff
sniff(prn = IP_sniff)
