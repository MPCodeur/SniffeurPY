from scapy.all import *
from scapy.config import conf
listProtos=[layer.__name__ for layer in conf.layers]

def sniffing():
    NbrPack=int(input("Combien de packet vous voulez sniff ? "))
    couche=input("Quel couche voulez-vous sniff ? ")
    if couche not in listProtos:
        print("la couche n'existe pas")
        exit(1)
    ip_check=input("Voulez vous check les address IP des packets ? Y/N \n")
    display=input("Voulez vous affichez les packets ? Y/N \n")
    packets=sniff(NbrPack)
    countIP = 0
    count_packet = 1
    NbrPack -= 1

    while NbrPack != -1:
        if packets[NbrPack].haslayer(couche):
            countIP += 1

            if ip_check == "Y":
                if packets[NbrPack].haslayer(IP) == True:
                    cap=packets[NbrPack]
                    print("IP source du packet " + str(count_packet) + "\n" + cap[IP].src + "\n")

            if display == "Y":
                packets[NbrPack].show()
                print("\n----------------------------------------------\n")
        count_packet += 1
        NbrPack -= 1
                    
        if NbrPack == -1:
            print("nombre de couche " + couche + " : " + str(countIP))
            exit()
    
sniffing()
