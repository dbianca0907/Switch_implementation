#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import configparser
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec():
    while True:
        # TODO Send BDPU every second if necessary
        time.sleep(1)

def forwarding(src_mac, dest_mac, interface, interfaces, MAC_table):
    MAC_table[src_mac] = interface
    chosen_interfaces = []

    if dest_mac != 'FF:FF:FF:FF:FF:FF':
        if dest_mac in MAC_table:
            #frames_list.append((MAC_table[dest_mac], data, length))
            chosen_interfaces.append(MAC_table[dest_mac])
        else:
            for o in interfaces:
                if o != interface:
                    #frames_list.append((o, data, length))
                    chosen_interfaces.append(o)
    else:
        for o in interfaces:
                if o != interface:
                    #frames_list.append((o, data, length))
                    chosen_interfaces.append(o)
    return MAC_table, chosen_interfaces


def read_from_config(config_file):
    table = {}
    info_list = []
    for line in config_file:
        info = line.strip().split()
        info_list.extend(info)
    for i in  range(1, len(info_list), 2):
        interface = info_list[i]
        vlan_id = info_list[i + 1] if i + 1 < len(info_list) else None
        table[interface] = vlan_id
    return table

def VLAN_support(VLAN_table, vlan_id, interface, chosen_interfaces, data, length):

    frames_list = []
    new_length = length
    new_data = data
    #if it arrives from trunk I erase the header
    name_src_interface = get_interface_name(interface)
    if VLAN_table[name_src_interface] == 'T':
        new_data = data[:12] + data[16:]
        new_length -= 4

    #if it goes to trunk I add header
    for i in chosen_interfaces:
        name_interface = get_interface_name(i)
        if VLAN_table[name_interface] == 'T':
            # interfata trunk => trebuie adaugat header
            print("Adauga header in trunk pentru: ", get_interface_name(i))
            vlan_tag = create_vlan_tag(vlan_id)
            new_data = data[:12] + vlan_tag + data[12:]
            new_length += 4
            frames_list.append((i, new_data, new_length))
            new_length -= 4
        else:
            # interfata pe care trebuie trimis este acces => se trimite in acelasi vlan
            print("Vland id este: ", vlan_id)
            #vine de pe trunk/access => trebuie sa verific daca e in acelasi vlan
            if int(VLAN_table[name_interface]) == (vlan_id - 4094) or VLAN_table[name_interface] == VLAN_table[name_src_interface]:
                print("Este adaugat in frames_list: ", get_interface_name(i))
                frames_list.append((i, new_data, new_length))

    return frames_list



def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]

    num_interfaces = wrapper.init(sys.argv[2:])
    interfaces = range(0, num_interfaces)
    chosen_interfaces = []
    VLAN_Table = {}
    MAC_table = {}


    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec)
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        print(f'Destination MAC: {dest_mac}')
        print(f'Source MAC: {src_mac}')
        print(f'EtherType: {ethertype}')

        print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # TODO: Implement forwarding with learning
        MAC_table, chosen_interfaces = forwarding(src_mac, dest_mac, interface, interfaces, MAC_table)

        for i in chosen_interfaces:
            print("INTERFETE ", get_interface_name(i))
        # keys_list = list(VLAN_Table.keys())
        # print(keys_list)
        # for i in keys_list:
        #     print("VALORILE", VLAN_Table[i])
        # TODO: Implement VLAN support
        config_file = open(f'configs/switch{switch_id}.cfg')
        VLAN_Table = read_from_config(config_file)
        frames_list = VLAN_support(VLAN_Table, vlan_id, interface, chosen_interfaces, data, length)
        # TODO: Implement STP support
        for (interface, data, length) in frames_list:
            print("Trimite in frames_list: ", get_interface_name(interface))
            send_to_link(interface, data, length)
        # data is of type bytes.
        # send_to_link(i, data, length)

if __name__ == "__main__":
    main()
