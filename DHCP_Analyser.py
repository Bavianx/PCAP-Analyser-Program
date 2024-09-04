import struct
import time
from Global_Header import extract_pcap_header

# this displays a hex dump taken from wireshark / 
hex_string = '5c260a02a8e400d0ba492ca1080045c001489b2c000040117cd6ac100401ac1004c10043004401342cf302010600374973ec00000000ac1004c100000000ac100401000000005c260a02a8e400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501053604ac1004010104ffffff001c04ac1004ff0604ac1004010304ac100401ff000000000000000'
dhcp_hex_frame = bytes.fromhex(hex_string)

# displays the mac, ips from the pcap file 
def source_mac(dhcp_hex_frame):
    src_mac_add = ':'.join('%02x' % b for b in dhcp_hex_frame)
    return src_mac_add
def destination_ip(dhcp_hex_frame):
    dest_ip_add = ':'.join(f'{b:02}' for b in dhcp_hex_frame)
    return dest_ip_add
def destination_mac(dhcp_hex_frame):
    dest_mac_add = ':'.join('%02x' % b for b in dhcp_hex_frame)
    return dest_mac_add
def source_ip(dhcp_hex_frame):
    src_ip_add = ':'.join(f'{b:02}' for b in dhcp_hex_frame)
    return src_ip_add


def analyse_pcap(file_path):
    with open(file_path, 'rb') as file:
        extracted_global_header_data, endianness, format = extract_pcap_header(file)

        while True:
            pcap_packet_header = file.read(16)
            if not pcap_packet_header:
                break

            timestamp_sec, timestamp_micro, included_len, original_len = struct.unpack(format + 'IIII', pcap_packet_header)
            packet_data = file.read(included_len)
            src_mac_add, dest_mac_add, eth_type = ethernet_frame(packet_data)

            if eth_type == 0x0800:  # IP packet
                src_ip_add, dest_ip_add, ip_payload = extract_ip_data(packet_data[14:])
                src_port, dest_port = struct.unpack('HH', ip_payload[:4])
                # this print out each packets information
                print("\033[1m" + "\n DHCP Packet Info: \n" + "\033[0m")
                print("- Timestamp:", timestamp_sec + timestamp_micro / 1e6)
                print("- GMT Time:", time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp_sec)))
                print("- DHCP Frame Length:", included_len)
                print("- Source MAC Address:", source_mac(src_mac_add))
                print("- Destination MAC Address:", destination_mac(dest_mac_add))
                print("- Source IP Address:", source_ip(src_ip_add))
                print("- Destination IP Address:", destination_ip(dest_ip_add))
                print ("- Host Name PC:", get_host_name())

 
# unpacks the information allowing it to be extracted
def ethernet_frame(frame):
    dest_mac_add, src_mac_add, eth_type = struct.unpack('!6s6sH', frame[:14])
    return src_mac_add, dest_mac_add, eth_type

 # extracts information from the header (src ip and dest ip)
def extract_ip_data(packet):
    if len(packet) <20:
        return ValueError("Packet is too small")
    version_and_header_length = packet[0]
    header_length = (version_and_header_length & 15) * 4
    src_ip_add = packet[12:16]
    dest_ip_add = packet[16:20]
    packet_data = packet[header_length:]
    return src_ip_add, dest_ip_add, packet_data

 #Reads the packet and outputs a tuple which returns the timestamped information
def read_packet(file, format):
    try:
        pcap_packet_header = file.read(16)
        timestamp_sec, timestamp_micro, included_len, original_len = struct.unpack(format + 'IIII', pcap_packet_header)
        packet = file.read(included_len)
        return (timestamp_sec, timestamp_micro, included_len), packet
    except:struct.error
    return None, None


def get_host_name():
    with open("CyberSecurity2024.pcap", 'rb') as file:
        pcap_header = file.read(24)
        packet_header = file.read(16)
        dhcp_frame = file.read(None)
        host_name = dhcp_frame[332:341]
    return(host_name) 


