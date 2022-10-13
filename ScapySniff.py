#on importe toutes les méthodes de la librairy 'scapy' ainsi que le dictionaire qui contient tout les types de packet possible
from scapy.all import *
from scapy.config import conf
listProtos=[layer.__name__ for layer in conf.layers]

def sniffing():
    #on récupère les informations pour notre programme
    NbrPack = int(input("Combien de packet vous voulez sniff ? "))
    couche = input("Quel couche voulez-vous sniff ? ")
    #on vérifie si la couche rentré existe bel et bien grace au dictionnaire, sinon on quitte le programme en notifiant l'utilisateur
    if couche not in listProtos:
        print("la couche n'existe pas")
        exit(1)
    ip_check=input("Voulez vous check les address IP source des packets ? Y/N \n")
    display=input("Voulez vous affichez les packets ? Y/N \n")
    packets=sniff(NbrPack) #on commence à sniff maintenant qu'on à un nombre déterminer de packet à sniff
    countIP = 0 #on va compter le nombre de fois que la couche recherché a correspondu aux packets trouvés 
    count_packet = 1 #pour compter le nombre de packet et savoir si où on en est dans la boucle while
    NbrPack -= 1 #pour décompter et s'arreter quand NbrPack arrive à -1 et pas 0 car cela est l'équivalent du premier élément

    while NbrPack != -1:
        #vérification si le packet sniffé a la couche demandé
        if packets[NbrPack].haslayer(couche):
            countIP += 1
            #si l'utilisateur veut afficher l'addresse IP source de chaque packet
            if ip_check == "Y":
                #si le packet à bel et bien un layer IP, on le stock dans une variable et on affiche l'IP source
                if packets[NbrPack].haslayer(IP) == True:
                    cap=packets[NbrPack]
                    print("IP source du packet " + str(count_packet) + "\n" + cap[IP].src + "\n")
            #si l'utilisateur veut afficher les packets, on l'affiche accompagner d'un séparateur
            if display == "Y":
                packets[NbrPack].show()
                print("\n----------------------------------------------\n")
        count_packet += 1
        NbrPack -= 1
        #si il n'y a plus de packet à sniff on s'occuper de l'affichage de fin
        #en donnant le nombre de packet trouvé coresspondant à la coucher recherché 
        if NbrPack == -1:
            print("nombre de couche " + couche + " : " + str(countIP))
            exit()
    
sniffing()
