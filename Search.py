import re
from Global_Header import extract_pcap_header
from DHCP_Analyser import read_packet

# sets up a list of commonly used search engines and compares it from the data inside the pcap file
def search_engine(file_path):
        search_engine_common = re.compile(r'(Brave\.com|bing\.com|duckduckgo\.com|yahoo\.com)/search\?q=([^&]+)')

        with open(file_path, 'rb') as file:
            extracted_global_header_data, endianness, format = extract_pcap_header(file)
            search_engine_info = []        
            unique_search_queries= set()

            
            while True:
                packet_info, packet = read_packet(file, format)
                if not packet:
                    break

                # search for search engine query
                packet_str = packet.decode('utf-8', 'ignore')
                search_match = search_engine_common.search(packet_str)
                if search_match:
                    search_engine, search_query = search_match.groups()
                    unique_query = (search_engine, search_query)
                    if unique_query not in unique_search_queries:
                        unique_search_queries.add(unique_query)
                        search_engine_info.append(unique_query)

            print("\033[1m" + "\n Engine Queries: \n" + "\033[0m")
            print("- Search Engine Queries:", search_engine_info)


        domain_pattern = re.compile(r'http://\S+\.com')
    
        with open(file_path, 'rb') as file:
            extracted_global_header_data, endianness, format = extract_pcap_header(file)
            suspected_domains = set()
        
            # Reads each DHCP frame/packet from the pcap file
            while True:
                packet_info, packet = read_packet(file, format)
                if not packet:
                    break
        
                # Searches for suspected domains
                packet_str = packet.decode('utf-8', 'ignore')
                suspected_domains.update(domain_pattern.findall(packet_str))
            print("- Suspected websites:", suspected_domains)