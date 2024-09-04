import re
from Global_Header import extract_pcap_header
from DHCP_Analyser import read_packet

# looks for websites that start with the http and ends in the .top
def bad_domain(file_path):
    suspected_domain = re.compile(r'http://\S+\.top')
  
    with open(file_path, 'rb') as file:
        extracted_global_header_data, endianness, format = extract_pcap_header(file)
        suspected_domains = set()
    
        #reads each dchp frame / packet from the pcap file
        while True:
            packet_info, packet = read_packet(file, format)
            if not packet:
                break
     
            # searches for suspected domains
            packet_str = packet.decode('utf-8', 'ignore')
            suspected_domains.update(suspected_domain.findall(packet_str))

        print("\033[1m" + "\n Bad Domain \n" + "\033[0m")
        print("- Suspected Domains:", suspected_domains)




 




