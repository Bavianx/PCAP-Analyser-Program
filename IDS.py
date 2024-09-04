

import struct
from Global_Header import extract_pcap_header

hex_string = '5c260a02a8e400d0ba492ca1080045c001489b2c000040117cd6ac100401ac1004c10043004401342cf302010600374973ec00000000ac1004c100000000ac100401000000005c260a02a8e400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000638253633501053604ac1004010104ffffff001c04ac1004ff0604ac1004010304ac100401ff000000000000000'
dhcp_hex_frame = bytes.fromhex(hex_string)

def source_ip(dhcp_hex_frame):
    src_ip_add = ':'.join(f'{b:02}' for b in dhcp_hex_frame)
    return src_ip_add


# this code is a modified version of DHCP Analyser that is used to get the inbound / source ip address flags any Malicious IPs

def ids(file_path):
    with open(file_path, 'rb') as file:
        extracted_global_header_data, endianness, format = extract_pcap_header(file)
        
        #Malicious IP list from https://www.projecthoneypot.org/list_of_ips.php
        MaliciousIP = ['60.17.154.251', '103.18.103.32', '172.245.12.85', '152.32.226.173', '182.87.64.117', '219.117.199.8', '103.18.103.43','74:125:141:100']
        inboundIP = [] #creates a blank list of inbound IPs
            
        while True:
            pcap_packet_header = file.read(16)
            if not pcap_packet_header:
                #create a set called Found MaliciousIP and puts all the inbound ip address and the one Malicious IP list if both are found it will 
                Found_MaliciousIP = set(inboundIP) & set(MaliciousIP)   
                if Found_MaliciousIP:
                    print("\n Malicious IP Address has been DETECTED ", Found_MaliciousIP) # display the list of which one are Malicious 
                else:
                    print("No Malicious IP address have been DETECTED ") #Display if no Malicious IP address have been DETECTED 
                break #ends the loop of all the packets 
            
            timestamp_sec, timestamp_micro, included_len, original_len = struct.unpack(format + 'IIII', pcap_packet_header) 
            packet_data = file.read(included_len)
            src_ip_add = extract_ip_data(packet_data[14:])
            inboundIP.append(source_ip(src_ip_add)) # appends ip address to the inbound IP address list 
 

 # extracts sourcse ip address from the header 
def extract_ip_data(packet):
    src_ip_add = packet[12:16]
    return src_ip_add




