import dpkt
import modified_pcap
import datetime


f = open('univ1_pt13', "rb")
pcap = modified_pcap.Reader(f)

packet_lengths = []
counter = 0
for ts, buf in pcap:
    print counter
    # print 'Timestamp: ' + str(datetime.datetime.utcfromtimestamp(ts))
    # print len(buf)
    # header = pcap._Reader__ph(buf)
    header = pcap.hdr
    packet_lengths.append(header.len)
    # print header.len
    counter += 1
    eth = dpkt.ethernet.Ethernet(buf)

    network = eth.data
    if type(network) == dpkt.ip.IP:
        # print "ip packet len:" + str(network.len)
        # print "ip header len:" + str(network.hl * 4)
        print dpkt.socket.inet_ntoa(network.src)
        print dpkt.socket.inet_ntoa(network.dst)
        transport = network.data
        if type(transport) == dpkt.tcp.TCP:
            print transport.dport
            print transport.sport
            print transport.flags
            print "TCP"
        elif type(transport) == dpkt.udp.UDP:
            print transport.dport
            print transport.sport
            print "UDP"
        else:
            print "Other"

#detect multi flow in one pair of host
    # start = 0
    # first_connection = True
    # syn_request = False
    # if library.SYN in value[0].flags:
    #     first_connection = False
    # for i in range(len(value)):
    #     pkt = value[i]
    #     if not first_connection and library.SYN in pkt.flags and library.ACK in pkt.flags:
    #         first_connection = True
    #     elif library.SYN in pkt.flags and i != 0 and first_connection:
    #         syn_request = True
    #         start = i
    #     elif library.SYN in pkt.flags and library.ACK in pkt.flags and syn_request:
    #         print str(pkt)

# check fin bits and reset bits in packets for end of stream for tcp
    # fin_num = 0
    # start = 0
    # for i in range(len(value)):
    #     pkt = value[i]
    #     if library.FIN in pkt.flags:
    #         fin_num += 1
    #     elif library.ACK in pkt.flags and fin_num == 2:
    #         # if i != len(value) - 1:
    #
    #         if key in keys:
    #             print pkt
    #         keys.append(key)
    #         fin_num = 0
    #         tcp_flows.append(library.Flow(library.TCP,value[start: i+1]))
    #         start = i + 1
    #     # multiple resets in a row. ?check next packet flags
    #     # elif library.RST in pkt.flags:
    #     #     if i == len(value) - 1 or library.RST not in value[i+1].flags:
    #     #         if i != len(value) - 1:
    #     #             print pkt
    #     #         fin_num = 0
    #     #         tcp_flows.append(library.Flow(library.TCP,value[start: i+1]))
    #     #         start = i + 1
    #     elif i == len(value) - 1:
    #         fin_num = 0
    #         tcp_flows.append(library.Flow(library.TCP,value[start: i+1]))
    #         start = i + 1
print len(packet_lengths)
packet_lengths.sort()
print packet_lengths[-1]
