from scapy.all import sniff, get_if_list, ICMP, TCP, UDP
import os
import sys
import ctypes

def sniff_and_identify(interface, count=10, timeout=5):
    """
    Sniffs network packets on the specified interface and allows protocol identification.

    Args:
        interface: The name of the network interface to sniff on.
        count: The number of packets to capture.
        timeout: Timeout for sniffing in seconds.

    Returns:
        A list of captured packets.
    """
    print("Capturing packets...")
    try:
        # Sniffing with a timeout and count limit to prevent indefinite waiting
        packets = sniff(iface=interface, count=count, timeout=timeout)
        print(f"Captured {len(packets)} packets.")
        return packets
    except Exception as e:
        print(f"Error capturing packets: {e}")
        return []

def identify_protocol(packet):
    """
    Identifies the protocol of the given packet.

    Args:
        packet: A Scapy packet object.

    Returns:
        A string representing the protocol name (e.g., "ICMP", "TCP", "UDP", "Unknown").
    """
    if ICMP in packet:
        return "ICMP"
    elif TCP in packet:
        return "TCP"
    elif UDP in packet:
        return "UDP"
    else:
        return "Unknown"

def check_admin_privileges():
    """Check if the script is running with administrative privileges (Windows)."""
    if os.name == 'nt':  # For Windows
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        if not is_admin:
            print("Error: Run this script with administrative privileges.")
            sys.exit(1)

if __name__ == "__main__":  # Corrected this line
    try:
        # Check for administrative privileges
        check_admin_privileges()

        # List all available network interfaces
        interfaces = get_if_list()

        if not interfaces:
            print("No network interfaces found.")
            sys.exit(1)

        print("Available interfaces:")
        for idx, iface in enumerate(interfaces):
            print(f"{idx}: {iface}")

        # Ask the user to choose an interface
        interface_idx = int(input("Enter the number corresponding to the network interface to sniff on: "))
        if interface_idx < 0 or interface_idx >= len(interfaces):
            raise ValueError("Invalid interface selection!")

        interface = interfaces[interface_idx]

        # Sniff packets on the chosen interface
        print(f"Sniffing on interface: {interface}")
        captured_packets = sniff_and_identify(interface)

        while True:
            # Allow the user to filter by protocol
            protocol_name = input("Enter protocol name (ICMP, TCP, UDP, or 'all'): ").lower()
            if protocol_name == 'all':
                for packet in captured_packets:
                    print(f"Protocol: {identify_protocol(packet)}")
            elif protocol_name in ["icmp", "tcp", "udp"]:
                for packet in captured_packets:
                    if identify_protocol(packet).lower() == protocol_name:
                        print(f"Found {protocol_name.upper()} packet.")
            else:
                print("Invalid protocol name. Please enter ICMP, TCP, UDP, or 'all'.")

            # Ask if the user wants to continue
            if input("Do you want to continue? (y/n): ").strip().lower() != 'y':
                break

    except PermissionError:
        print("Error: Run this script with administrative privileges.")
    except ValueError as ve:
        print(f"ValueError occurred: {ve}")
    except Exception as e:
        print(f"An error occurred: {e}")
