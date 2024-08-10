from scapy.all import *
import argparse
import psutil

def get_active_interface():
    interfaces = psutil.net_if_addrs()
    for iface, addrs in interfaces.items():
        for addr in addrs:
            if addr.family == 2:  # AF_INET (IPv4)
                return iface
    raise Exception("No active network interface found")

def modify_ip_header(packet, new_ip):
    packet[IP].src = new_ip
    del packet[IP].chksum
    return packet

def modify_tcp_toa(packet, toa_ip):
    toa_option = TCPOption(kind=26, length=6, value=toa_ip)
    existing_option = None
    for option in packet[TCP].options:
        if option[0] == 26:
            existing_option = option
            break
    
    if existing_option:
        packet[TCP].options = [(26, toa_ip) if opt[0] == 26 else opt for opt in packet[TCP].options]
    else:
        packet[TCP].options.append(('TOA', toa_ip))
    
    del packet[TCP].chksum
    return packet

def packet_callback(packet, new_ip, toa_ip):
    if IP in packet and TCP in packet:
        packet = modify_ip_header(packet, new_ip)
        packet = modify_tcp_toa(packet, toa_ip)
        send(packet, verbose=False)

def main():
    parser = argparse.ArgumentParser(description="Modify TCP/IP packet headers")
    parser.add_argument("--new_ip", help="New IP address to set in the IP header", required=True)
    parser.add_argument("--toa_ip", help="IP address to set in TOA TCP option", required=True)
    parser.add_argument("--interface", help="Network interface to capture packets from")
    args = parser.parse_args()

    if not args.interface:
        args.interface = get_active_interface()
        print(f"No interface specified. Using the active interface: {args.interface}")
    
    sniff(iface=args.interface, prn=lambda pkt: packet_callback(pkt, args.new_ip, args.toa_ip))

if __name__ == "__main__":
    main()
