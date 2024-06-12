import socket
import struct
import textwrap
import sys

class Color:
    RESET = '\033[0m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def main():
    connection = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    print("Begin listen?")
    while True:
        raw_data = connection.recvfrom(65536)
        dest_mac, source_mac, type_protocol, data = ethernet_frame(raw_data[0])
        print('\n{}[+] Ethernet Frame{}: '.format(Color.YELLOW, Color.RESET))
        print('{}Destination{}: {}, {}Source{}: {}, {}type_protocolcol{}: {}\n'.format(Color.GREEN, Color.RESET, dest_mac, Color.GREEN, Color.RESET, source_mac, Color.GREEN, Color.RESET, type_protocol))
        
        if type_protocol== 0x8:
            version, header_length, ttl, protocol, source, target, data = unpacking_ipv4(data)
            print('--->' + '{}IPv4 Packet{}: '.format(Color.CYAN, Color.RESET))
            print('\t\t' + '{}Version{}: {}, {}Header Length{}: {}, {}TTL{}: {}'.format(Color.GREEN, Color.RESET, version, Color.GREEN, Color.RESET, header_length, Color.GREEN, Color.RESET, ttl))
            print('\t\t' + '{}protocolcol{}: {}, {}Source{}: {}, {}Target{}: {}'.format(Color.GREEN, Color.RESET, protocol, Color.GREEN, Color.RESET, source, Color.GREEN, Color.RESET, target))
                icmp_type, code, checksum, data = unpacking_icmp(data)
                print('------>' + '{}ICMP PACKET{}: '.format(Color.MAGENTA, Color.RESET))
                print('\t\t' + '{}Type{}: {}, {}Code{}: {}, {}Checksum{}: {}'.format(Color.GREEN, Color.RESET, icmp_type, Color.GREEN, Color.RESET, code, Color.GREEN, Color.RESET, checksum))
                print('\t\t' + '{}Data{}: {}'.format(Color.GREEN, Color.RESET, data))
                        
            elif protocol == 6:
                source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data = unpacking_tcp(data)
                print('------>' + '{}TCP Segment{}: '.format(Color.MAGENTA, Color.RESET))
                print('\t\t' + '{}Source Port{}: {}, {}Destination Port{}: {} '.format(Color.GREEN, Color.RESET, source_port, Color.GREEN, Color.RESET, destination_port))
                print('\t\t' + '{}Sequence{}: {}, {}Acknowledgment{}: {}'.format(Color.GREEN, Color.RESET, sequence, Color.GREEN, Color.RESET, acknowledgement))
                print('\t\t' + '{}Flags{}:  URG: {}, ACK: {}, PSH: {}, RST: {}, SYN: {}, FIN: {}'.format(Color.GREEN, Color.RESET, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin))
                print('\t\t' + '{}Data{}: {}'.format(Color.GREEN, Color.RESET, data))

            elif protocol == 17:
                source_port, destination_port, length, data = unpacking_udp(data)
                print('------>' + '{}UDP Segment{}: '.format(Color.MAGENTA, Color.RESET))
                print('\t\t' + '{}Source Port{}: {}, {}Destination Port{}: {}, {}Length{}: {}'.format(Color.GREEN, Color.RESET, source_port, Color.GREEN, Color.RESET, destination_port, Color.GREEN, Color.RESET, length))
                print('\t\t' + '{}Data{}: {}'.format(Color.GREEN, Color.RESET, data))

            else:
                print('\t\t' + '{}Data{}: {}'.format(Color.GREEN, Color.RESET, data))

        elif type_protocol== 0x0608:
            hardware_type, protocolcol_type, opcode, sender_mac, sender_ip, target_mac, target_ip = unpacking_arp(data)
            print('--->' + '{}ARP Packet{}: '.format(Color.CYAN, Color.RESET))
            print('\t\t' + '{}Hardware type{}: {}, {}protocolcol{}: {}, {}Opcode{}: {}'.format(Color.GREEN, Color.RESET, hardware_type, Color.GREEN, Color.RESET, protocolcol_type, Color.GREEN, Color.RESET, opcode))
            print('\t\t' + '{}Sender MAC{}: {}, {}Sender IP{}: {}, {}Target MAC{}: {}, {}Target IP{}: {}'.format(Color.GREEN, Color.RESET, sender_mac, Color.GREEN, Color.RESET, sender_ip, Color.GREEN, Color.RESET, target_mac, Color.GREEN, Color.RESET, target_ip))

        else:
            print('\t\t' + '{}Data{}: {}'.format(Color.GREEN, Color.RESET, data))


def ethernet_frame(data):
    dest_mac, source_mac, protocol = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(source_mac), socket.htons(protocol), data[14:]


def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    return ':'.join(bytes_str).upper()


def unpacking_ipv4(data):
    version_header_length = data[0]
    version = version_header_length >> 4
    header_length = (version_header_length & 15)  * 4 # на 4 потому что отчет по словам, а не байтам
    ttl, protocol, source, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
    return version, header_length, ttl, protocol, ipv4(source), ipv4(target), data[header_length:]


def ipv4(addr):
    return '.'.join(map(str, addr))
 
def unpacking_arp(data):
    hardware_type, protocolcol_type  = struct.unpack('! H H', data[:4])
    opcode, sender_mac, sender_ip, target_mac, target_ip = struct.unpack('! H 6s 4s 6s 4s', data[6:])
    return hardware_type, protocolcol_type, opcode, get_mac_addr(sender_mac), ipv4(sender_ip), get_mac_addr(target_mac), ipv4(target_ip)

def unpacking_icmp(data):
    icmp_type, code, checksum = struct.unpack('! B B H', data[:4])
    return  icmp_type, code, checksum, data[4:]


def unpacking_tcp(data):
    source_port, destination_port, sequence, acknowledgement, offset_reserved_flags = struct.unpack('! H H L L H', data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    flag_psh = (offset_reserved_flags & 8) >> 3
    flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = (offset_reserved_flags & 1)
    return source_port, destination_port, sequence, acknowledgement, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, data[offset:]
 
 
def unpacking_udp(data):
    source_port, destination_port, size = struct.unpack('! H H 2x H', data[:8])
    return source_port, destination_port, size, data[8:]
 
main()