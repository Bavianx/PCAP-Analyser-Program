
import struct

def extract_pcap_header(file):
    pcap_header_data = file.read(24)
    if len(pcap_header_data) != 24:
        raise ValueError("Invalid pcap file: Header size is not 24 bytes.")

    magic_number = pcap_header_data[:4]
    if magic_number == b'\xa1\xb2\xc3\xd4':
        endianness = "big"
    elif magic_number == b'\xd4\xc3\xb2\xa1':
        endianness = "little"
    else:
        raise ValueError("Invalid pcap file: Header size is not 24 bytes.")

    format = '>' if endianness == 'big' else '<'
    version_major, version_minor, thiszone, sigfigs, snaplen, network = struct.unpack(format + 'HHIIII', pcap_header_data[4:])
    
    # analyses the information from the global header and outputs it through the following
    output = (
        f"- Length of Global Header: 24\n"
        f"- Magic Number: {magic_number.hex()}\n"
        f"- Endianness: {endianness}\n"
        f"- Version Major: {version_major}\n"
        f"- Version Minor: {version_minor}\n"
        f"- SnapLength: {snaplen}\n" 
        f"- Data Link Type: {network}"
    )

    return output, endianness, format