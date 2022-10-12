from scapy.all import *
import keyboard

ip_source = input("Quel est l'IP à surveiller ?\n")

def DNS_sniff(packets):
    if (str(packets[IP].src)) == (str(ip_source)):
        if packets.haslayer(DNS) and packets.getlayer(DNS).qr == 0:
            print ("requête DNS vers: " + (packets.getlayer(DNS).qd.qname).decode('utf-8'))


sniff(filter = "port 53", prn = DNS_sniff)
