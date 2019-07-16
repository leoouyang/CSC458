import dpkt
import modified_pcap
import library
import pickle

f = open('univ1_pt13', "rb")
# f = open('small.pcap', "rb")
pcap = modified_pcap.Reader(f)

total_num = 0
tcp_dict = {}
udp_dict = {}

# larger first
# construct ip and tcp into following form as a key
# the one with larger ip address is the first one
# key would be the same for both direction
# "192.168.0.1:29832-121.125.214.213:21523"
for ts, buf in pcap:
    total_num += 1
    orig_len = pcap.hdr.len
    #for some reason, many packets with 0 data is 64 byte on wire, 60 bytes captured
    # Padding in header
    # all_header_size = max(len(buf),64)

    # Already know from wireshark that all packets in pcap is using Ethernet
    eth = dpkt.ethernet.Ethernet(buf)
    if total_num % 100000 == 0:
        print total_num

    if type(eth.data) == dpkt.ip.IP or type(eth.data) == dpkt.ip6.IP6:
        ip = eth.data
        ip_src = library.inet_to_str(ip.src)
        ip_dst = library.inet_to_str(ip.dst)

        if type(ip.data) == dpkt.udp.UDP:
            udp_pkt = ip.data
            packet = library.Packet(ts, orig_len, library.UDP, ip_src, ip_dst, udp_pkt)
            key = library.construct_key(ip_src, ip_dst, udp_pkt.sport, udp_pkt.dport)
            if key in udp_dict:
                udp_dict[key].append(packet)
            else:
                # print key
                udp_dict[key] = [packet]
        elif type(ip.data) == dpkt.tcp.TCP:
            tcp_pkt = ip.data

            ip_data_size = ip.len - ip.hl * 4
            packet = library.Packet(ts, orig_len, library.TCP, ip_src, ip_dst, tcp_pkt,ip_data_size)
            key = library.construct_key(ip_src, ip_dst, tcp_pkt.sport, tcp_pkt.dport)
            if key in tcp_dict:
                tcp_dict[key].append(packet)
            else:
                # print key
                tcp_dict[key] = [packet]

# since the pcap record file is only 5 min long
# don't need to check for 90min separation when constructing flow

udp_flows = []
tcp_flows = []
udp_total_bytes = 0
tcp_total_bytes = 0

for key, value in udp_dict.iteritems():
    udp_flow = library.Flow(library.UDP,value)
    udp_total_bytes += udp_flow.total_bytes
    udp_flows.append(udp_flow)


for key, value in tcp_dict.iteritems():
    tcp_flow = library.Flow(library.TCP, value)
    tcp_total_bytes += tcp_flow.total_bytes
    tcp_flows.append(tcp_flow)

#Flow Type
print "UDP count: " + str(len(udp_flows))
print "UDP percentage: "+ str(len(udp_flows)*100.0/(len(udp_flows) + len(tcp_flows)))
print "UDP total bytes: " + str(udp_total_bytes)
print "TCP count: " + str(len(tcp_flows))
print "TCP percentage: "+ str(len(tcp_flows)*100.0/(len(udp_flows) + len(tcp_flows)))
print "TCP total bytes: " + str(tcp_total_bytes)

#Flow Duration
udp_flows_durations = []
for flow in udp_flows:
    udp_flows_durations.append(flow.end-flow.start)
library.plot_cdf(udp_flows_durations, "UDP flow durations", "duration", logarithmic=False)

tcp_flows_durations = []
for flow in tcp_flows:
    tcp_flows_durations.append(flow.end-flow.start)
library.plot_cdf(tcp_flows_durations, "TCP flow durations", "duration", logarithmic=False)

all_durations = udp_flows_durations + tcp_flows_durations
library.plot_cdf(all_durations, "All flow durations", "duration", logarithmic=False)

#Flow size
udp_flows_sizes_byte = []
udp_flows_sizes_packet = []
for flow in udp_flows:
    udp_flows_sizes_byte.append(flow.total_bytes)
    udp_flows_sizes_packet.append(len(flow.packets))
library.plot_cdf(udp_flows_sizes_byte, "UDP flow size byte count", "log2(size)")
library.plot_cdf(udp_flows_sizes_packet, "UDP flow size packet count", "log2(size)")

tcp_flows_sizes_byte = []
tcp_flows_sizes_packet = []
tcp_flows_header_data_ratio = []
for flow in tcp_flows:
    tcp_flows_sizes_byte.append(flow.total_bytes)
    tcp_flows_sizes_packet.append(len(flow.packets))
    if flow.total_data == 0:
        # print "0 data size, packets: " + str(len(flow.packets))
        tcp_flows_header_data_ratio.append(9999)
    else:
        tcp_flows_header_data_ratio.append((flow.total_bytes - flow.total_data)*1.0/flow.total_data)
library.plot_cdf(tcp_flows_sizes_byte, "TCP flow size byte count", "log2(size)")
library.plot_cdf(tcp_flows_sizes_packet, "TCP flow size packet count", "log2(size)")
library.plot_cdf(tcp_flows_header_data_ratio, "TCP overhead ratio", "log2(ratio)")

all_sizes_byte = udp_flows_sizes_byte + tcp_flows_sizes_byte
library.plot_cdf(all_sizes_byte, "All flow size byte count", "log2(size)")
all_sizes_packet = udp_flows_sizes_packet + tcp_flows_sizes_packet
library.plot_cdf(all_sizes_packet, "All flow size packet count", "log2(size)")

#inter-packet arrival time
udp_times = []
for flow in udp_flows:
    udp_times.extend(flow.get_inter_packet_arrival_times())
library.plot_cdf(udp_times, "UDP flow inter arrival time", "time", logarithmic=False)

tcp_times = []
for flow in tcp_flows:
    tcp_times.extend(flow.get_inter_packet_arrival_times())
library.plot_cdf(tcp_times, "TCP flow inter arrival time", "time", logarithmic=False)

all_times = udp_times + tcp_times
library.plot_cdf(all_times, "All flow inter arrival time", "time", logarithmic=False)

#TCP State
#The length of pcap is only 4 minute, link can't be in failed state
request_state = 0
reset_state = 0
finished_state = 0
ongoing_state = 0
for flow in tcp_flows:
    terminated = False
    a = flow.ip_src
    b = flow.ip_dst
    a2b_fin_seq = -1
    b2a_fin_seq = -1
    a2b_ack = -1
    b2a_ack = -1

    only_syn = True
    reset = False
    for packet in flow.packets:
        flags = packet.get_flags()
        if only_syn and library.SYN not in flags:
            only_syn = False
        if library.RST in flags:
            reset = True
        if library.FIN in flags:
            if packet.ip_src == a:
                if a2b_fin_seq == -1:
                    a2b_fin_seq = packet.seq
                else:
                    a2b_fin_seq = min(packet.seq, a2b_fin_seq)
            if packet.ip_src == b:
                if b2a_fin_seq == -1:
                    b2a_fin_seq = packet.seq
                else:
                    b2a_fin_seq = min(packet.seq, b2a_fin_seq)
        if library.ACK in flags:
            if packet.ip_src == a:
                a2b_ack = packet.ack
            if packet.ip_src == b:
                b2a_ack = packet.ack

    # in the situation that both rst and fin are used to terminate,
    # I count toward fin if the fin ack fin ack process is completed
    if only_syn:
        request_state += 1
        terminated = True
    elif a2b_fin_seq != -1 and b2a_fin_seq != -1 and b2a_ack >= a2b_fin_seq and a2b_ack >= b2a_fin_seq:
        finished_state += 1
        terminated = True
    elif reset:
        reset_state += 1
        terminated = True
    elif not terminated:
        ongoing_state += 1
print "Final State Request: " + str(request_state)
print "Final State Reset: " + str(reset_state)
print "Final State Finished: " + str(finished_state)
print "Final State Ongoing: " + str(ongoing_state)
print len(tcp_flows)

#store the flows we are going to use in the next section
required_flows = {}
largest_packet_number = sorted(tcp_flows, key=lambda flow:len(flow.packets),reverse=True)
required_flows["packet_number"] = largest_packet_number[0:3]
largest_total_byte = sorted(tcp_flows, key=lambda flow:flow.total_bytes,reverse=True)
required_flows["total_byte"] = largest_total_byte[0:3]
longest_duration = sorted(tcp_flows, key=lambda flow:flow.end - flow.start,reverse=True)
required_flows["duration"] = longest_duration[0:3]
binary_file = open('required_flows',mode='wb')
pickle.dump(required_flows, binary_file, -1)
binary_file.close()

#find 3 pair of the hosts with highest number of TCP connections
host_pair_dict = {}
for flow in tcp_flows:
    if flow.ip_src > flow.ip_dst:
        key = flow.ip_src + "," + flow.ip_dst
    else:
        key = flow.ip_dst + "," + flow.ip_src

    if key in host_pair_dict:
        host_pair_dict[key].append(flow)
    else:
        host_pair_dict[key] = [flow]

result = sorted(host_pair_dict.values(), key=lambda x:len(x), reverse=True)[0:3]
binary_file = open('host_pairs',mode='wb')
pickle.dump(result, binary_file, -1)
binary_file.close()
# print result[0]
# print len(result)
# print len(result[0])
# print len(result[1])
# print len(result[2])
