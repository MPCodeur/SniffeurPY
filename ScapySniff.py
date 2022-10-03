from scapy.all import *
from scapy.config import conf
listProtos=[layer.__name__ for layer in conf.layers]

pack = None

def sniffing():
    num=int(input("Combien de packet vous voulez sniff ? "))
    couche=input("Quel couche voulez-vous sniff ? ")
    if couche not in listProtos:
        print("la couche n'existe pas")
        exit(1)

    ip_check=input("Voulez vous check les address IP des packets ? Y/N \n")
    display=input("Voulez vous affichez les packets ? Y/N \n")
    packets=sniff(num)
    countIP = 0
    count = 1
    readPack= num - 1

    if readPack == -1:
        exit()
    while readPack != -1:
        if packets[readPack].haslayer(couche):
            countIP += 1
        if ip_check == "Y":
            if packets[readPack].haslayer(IP) == True:
                cap=packets[readPack]
                print("IP source du packet " + str(count) + "\n" + cap[IP].src + "\n")
        count += 1
        if display == "Y":
            pack=packets[readPack].show()
            print("\n----------------------------------------------\n")
        readPack = readPack - 1
        if readPack == -1:
            print("nombre de couche " + couche + " : " + str(countIP))
            exit()
    return pack

sniffing()


