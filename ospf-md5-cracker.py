import sys
import hashlib
import binascii
import pyshark

FILETYPES = ['pcap', 'pcapng', 'cap']

def get_packets_hex(file):
    try:
        packets = pyshark.FileCapture(file, display_filter="ospf.msg == 1", use_json=True, include_raw=True)
    except FileNotFoundError:
        print(f"Error: The file '{file}' was not found")
        sys.exit(1)

    packets_hex = []
    for packet in packets:
        packets_hex.append(packet.ospf.header_raw[0] + packet.ospf.hello_raw[0] + "$" + packet.ospf.header.data_raw[0])
    return packets_hex

def crack_md5(packets_hex, wordlist_path):
    for packet in packets_hex:
        print(packet)
        try:
            with open(wordlist_path, 'r', errors='replace') as file:
                words = file.readlines()
        except FileNotFoundError:
            print(f"Error: The file '{wordlist_path}' was not found")
            sys.exit(1)

        target_hash = packet.split('$')[1]
        packet_bytes = binascii.unhexlify(packet.split('$')[0])
        found_key = None

        print (f"Bruteforcing with '{wordlist_path}' ...")
        for word in words:
            key = word.strip()
            to_hash = packet_bytes + key.encode('utf-8')
            md5_hash = hashlib.md5(to_hash).hexdigest()

            if md5_hash == target_hash:
                found_key = key
                break

        if found_key:
            print(f"Key found: {found_key}\n")
        else:
            print("No matching key found!\n")

if __name__ == "__main__":
    try:
        match len(sys.argv):
            case 2:
                if sys.argv[1].split('.')[1] not in FILETYPES:
                    print("Error: Incorrect file type, must be in " + FILETYPES.__repr__())
                    sys.exit(1)
                packets_hex = get_packets_hex(sys.argv[1])
                for packet in packets_hex:
                    print("$netmd5$" + packet)
            case 3:
                if sys.argv[1].split('.')[1] not in FILETYPES:
                    print("Error: Incorrect file type, must be in " + FILETYPES.__repr__())
                    sys.exit(1)
                packets_hex = get_packets_hex(sys.argv[1])
                crack_md5(packets_hex, sys.argv[2])
            case _:
                print("Usage: python ospf-md5-cracker.py <capture>* <wordlist>")
                sys.exit(1)
    except KeyboardInterrupt:
        print()
        sys.exit(1)
