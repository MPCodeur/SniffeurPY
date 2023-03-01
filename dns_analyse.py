import sys, time, csv
from scapy.all import *

#Check si il y a 3 arguments
if len(sys.argv) != 3:
   print("Veuillez fournir un fichier .cap ou .pcap et un nom de domaine en entrée\n")
   exit(1)

#Lis le fichier cap ou pcap puis on stock les packets DNS dans dns_packet
packets = rdpcap(sys.argv[1])
dns_packets = [i for i in packets if i.haslayer(DNS) and sys.argv[2] in i[DNS].qd.qname.decode("utf-8")]
#On met nos packet dns dans le fichier dns.pcap
out_pcap_file = "dns.pcap"
wrpcap(out_pcap_file, dns_packets)

def extract_dns():
   #on créer un dictionnaire et on y range toutes les informations importantes dedans pour le return à la fin
   ip_name = {}

   for i in dns_packets:
      src_ip = i[IP].src
      dst_ip = i[IP].dst

      if i.haslayer(DNSRR):
         resolved_name = i[DNSRR].rdata
      else:
         resolved_name = None
      ip_name[src_ip] = resolved_name
      ip_name[dst_ip] = resolved_name
   return (ip_name)


def CsvMaker(ip_name):
   #Ici on créer notre dns.csv, on y met l'en-tete puis toutes les infos contenus dans le dictionnaire
   stats_file = "dns.csv"
   with open(stats_file, 'w', newline='') as csvfile:
      writer = csv.writer(csvfile, delimiter=';')
      writer.writerow(["Horodatage", "IP source", "IP destination", "Adresse IP résolue"])
      
      for p in dns_packets:
         src_ip = p[IP].src
         dst_ip = p[IP].dst
         if p.haslayer(DNSRR):
            resolved_ips = p[DNSRR].rdata
         else:
            resolved_ips = None
         
         timestamp = time.strftime("%H:%M:%S %d/%m/%Y", time.localtime(float(p.time)))
         writer.writerow([timestamp, src_ip, dst_ip, resolved_ips])
         

#On fais appel à nos fonction et on previent l'utilisateur que tout c'est bien passé
ip_name_c = extract_dns()
CsvMaker(ip_name_c)
print("Resultats sauvegarder dans dns.csv et dns.pcap")
