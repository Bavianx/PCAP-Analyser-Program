
from Global_Header import extract_pcap_header
from DHCP_Analyser import analyse_pcap
from Bad_Domain import bad_domain
from Search import search_engine
from IDS import ids

print("  _____   _____          _____                         _                      ")
print(" |  __ \ / ____|   /\   |  __ \      /\               | |                     ")
print(" | |__) | |       /  \  | |__) |    /  \   _ __   __ _| |_   _ ___  ___ _ __  ")
print(" |  ___/| |      / /\ \ |  ___/    / /\ \ | '_ \ / _` | | | | / __|/ _ \ '__| ")
print(" | |    | |____ / ____ \| |       / ____ \| | | | (_| | | |_| \__ \  __/ |    ")
print(" |_|     \_____/_/    \_\_|      /_/    \_\_| |_|\__,_|_|\__, |___/\___|_|    ")

print("                                                          __/ |               ")
print("                                                         |___/                ")

def main():
    file_path = 'CyberSecurity2024.pcap'
    try:
        with open(file_path, 'rb') as file:
            extracted_global_header_data, endianness, format = extract_pcap_header(file)
            # this section below is used to select which part of the program you want to run
            while True:
                print("\n Menu Options:")
                print("1 - Global Header Info")
                print("2 - Analyse PCAP")
                print("3 - Check for Bad Domain")
                print("4 - Search Engine")
                print("5 - IP Checker")
                print("6 - Exit")
            
                try:
                    option = int(input("Enter your choice: "))
                    if option < 1 or option > 6:
                        raise ValueError("Option must be a number between 1 and 6")

                except ValueError as validation:
                    print("Error:", validation)
                    continue
            
                if option == 1:
                    print("\n Global Header Info: " + "\n", extracted_global_header_data)
            
                elif option == 2:
                    analyse_pcap(file_path)
            
                elif option == 3:
                    bad_domain(file_path)
            
                elif option == 4:
                    search_engine(file_path)
                    
                elif option == 5:
                    ids(file_path)
            
                elif option == 6:
                    print("Exiting...")
                    break

    # this will handle any error with opening files
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
    except ValueError as ve: 
        print(f"Error: {ve}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()