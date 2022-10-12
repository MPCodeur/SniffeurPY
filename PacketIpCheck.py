from scapy.all import *
import os


ip_source = input("Quel est l'IP à surveiller ?\n")

def IP_sniff(packets):
    if packets.haslayer(IP):
        if (str(packets[IP].src)) == (str(ip_source)):
            print("IP source trouvé")
            PackCheck = input("Voulez-vous afficher le packet ou quitter ? (Y/Q) ")

            if str(PackCheck) == 'Y':
                os.system('clear')
                packets.show()
            elif str(PackCheck) == 'Q':
                exit()
    
sniff(prn = IP_sniff)
