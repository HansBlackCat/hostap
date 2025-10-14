#!/usr/bin/env python3
"""
EAPOL Frame Capture Tool
Captures 802.1X EAPOL frames using raw sockets
"""

import socket
import struct
import sys
from datetime import datetime

# EAPOL EtherType
ETHERTYPE_EAPOL = 0x888E

def create_raw_socket(interface):
    """Create a raw socket bound to the interface"""
    try:
        # Create raw socket
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_EAPOL))
        sock.bind((interface, 0))
        return sock
    except PermissionError:
        print("Error: Need root/CAP_NET_RAW privileges")
        sys.exit(1)
    except OSError as e:
        print(f"Error creating socket: {e}")
        sys.exit(1)

def parse_ethernet(data):
    """Parse Ethernet header"""
    dest_mac = ':'.join(f'{b:02x}' for b in data[0:6])
    src_mac = ':'.join(f'{b:02x}' for b in data[6:12])
    ethertype = struct.unpack('!H', data[12:14])[0]
    return dest_mac, src_mac, ethertype, data[14:]

def parse_eapol(data):
    """Parse EAPOL packet"""
    if len(data) < 4:
        return None

    version = data[0]
    packet_type = data[1]
    length = struct.unpack('!H', data[2:4])[0]

    packet_types = {
        0: 'EAP-Packet',
        1: 'EAPOL-Start',
        2: 'EAPOL-Logoff',
        3: 'EAPOL-Key',
        4: 'EAPOL-Encapsulated-ASF-Alert'
    }

    return {
        'version': version,
        'type': packet_types.get(packet_type, f'Unknown({packet_type})'),
        'length': length,
        'payload': data[4:4+length]
    }

def analyze_eapol_key(payload):
    """Analyze EAPOL-Key frame for 4-way handshake"""
    if len(payload) < 95:
        return "Incomplete EAPOL-Key"

    descriptor_type = payload[0]
    key_info = struct.unpack('!H', payload[1:3])[0]

    # Extract key information bits
    key_descriptor_version = (key_info >> 0) & 0x07
    key_type = (key_info >> 3) & 0x01  # 0=Group, 1=Pairwise
    key_index = (key_info >> 4) & 0x03
    install = (key_info >> 6) & 0x01
    key_ack = (key_info >> 7) & 0x01
    key_mic = (key_info >> 8) & 0x01
    secure = (key_info >> 9) & 0x01
    error = (key_info >> 10) & 0x01
    request = (key_info >> 11) & 0x01
    encrypted_key_data = (key_info >> 12) & 0x01

    # Determine 4-way handshake message number
    msg = "Unknown"
    if key_type == 1:  # Pairwise key
        if key_ack and not key_mic:
            msg = "Message 1/4 (ANonce)"
        elif not key_ack and key_mic and not install and not encrypted_key_data:
            msg = "Message 2/4 (SNonce)"
        elif key_ack and key_mic and install and encrypted_key_data:
            msg = "Message 3/4 (GTK)"
        elif not key_ack and key_mic and not install and secure:
            msg = "Message 4/4 (ACK)"

    return f"EAPOL-Key: {msg} (ACK={key_ack}, MIC={key_mic}, Install={install}, Secure={secure})"

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        print(f"Example: {sys.argv[0]} wlan0")
        sys.exit(1)

    interface = sys.argv[1]
    print(f"[*] Starting EAPOL capture on {interface}")
    print(f"[*] Listening for 802.1X frames (EtherType 0x{ETHERTYPE_EAPOL:04X})")
    print(f"[*] Press Ctrl+C to stop\n")

    sock = create_raw_socket(interface)
    count = 0

    try:
        while True:
            data, addr = sock.recvfrom(65535)
            count += 1

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Parse Ethernet header
            dest_mac, src_mac, ethertype, payload = parse_ethernet(data)

            print(f"\n[{timestamp}] EAPOL Frame #{count}")
            print(f"  {src_mac} -> {dest_mac}")

            # Parse EAPOL
            eapol = parse_eapol(payload)
            if eapol:
                print(f"  EAPOL Version: {eapol['version']}")
                print(f"  Packet Type: {eapol['type']}")
                print(f"  Length: {eapol['length']}")

                # If it's an EAPOL-Key frame, analyze further
                if eapol['type'] == 'EAPOL-Key':
                    key_info = analyze_eapol_key(eapol['payload'])
                    print(f"  {key_info}")

            # Print raw hex (first 64 bytes)
            hex_data = ' '.join(f'{b:02x}' for b in data[:64])
            print(f"  Raw: {hex_data}...")

    except KeyboardInterrupt:
        print(f"\n\n[*] Captured {count} EAPOL frames")
        print("[*] Exiting...")
        sock.close()

if __name__ == "__main__":
    main()
