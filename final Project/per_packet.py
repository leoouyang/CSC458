import dpkt
import modified_pcap
import library

f = open('univ1_pt13', "rb")
pcap = modified_pcap.Reader(f)

total_num = 0

eth_num = 0
eth_size = 0
arp_num = 0
arp_size = 0

ip_num = 0
ip_size = 0
ipv6_num = 0
ipv6_size = 0
icmp_num = 0
icmp_size = 0
network_other_num = 0
network_other_size = 0

tcp_num = 0
tcp_size = 0
udp_num = 0
udp_size = 0
transport_other_num = 0
transport_other_size = 0

size_list = []
tcp_size_list = []
udp_size_list = []
ip_size_list = []
non_ip_size_list = []

tcp_header_size_list = []
ip_header_size_list = []

for ts, buf in pcap:
    total_num += 1
    if total_num % 100000 == 0:
        print total_num

    orig_len = pcap.hdr.len
    size_list.append(orig_len)

    # Already know from wireshark that all packets in pcap is using Ethernet
    eth = dpkt.ethernet.Ethernet(buf)
    eth_num += 1
    eth_size += orig_len

    if type(eth.data) != dpkt.ip.IP and type(eth.data) != dpkt.ip6.IP6:
        non_ip_size_list.append(orig_len)

    if type(eth.data) == dpkt.arp.ARP:
        arp_num += 1
        arp_size += orig_len
    elif type(eth.data) == dpkt.ip.IP:
        ip = eth.data
        # only count toward ipv4 if it is not ICMP4
        if type(ip.data) != dpkt.icmp.ICMP:
            ip_num += 1
            ip_size += orig_len
            ip_size_list.append(orig_len)
            ip_header_size_list.append(ip.hl * 4)

        if type(ip.data) == dpkt.icmp.ICMP:
            icmp_num += 1
            icmp_size += orig_len
        elif type(ip.data) == dpkt.udp.UDP:
            udp_num += 1
            udp_size += orig_len
            udp_size_list.append(orig_len)
        elif type(ip.data) == dpkt.tcp.TCP:
            tcp_num += 1
            tcp_size += orig_len
            tcp_size_list.append(orig_len)

            tcp = ip.data
            tcp_header_size_list.append(tcp.off*4)
        else:
            transport_other_num += 1
            transport_other_size += orig_len
    elif type(eth.data) == dpkt.ip6.IP6:
        ipv6 = eth.data
        #only count toward ipv6 if it is not ICMP6
        if type(ipv6.data) != dpkt.icmp6.ICMP6:
            ipv6_num += 1
            ipv6_size += orig_len
            ip_size_list.append(orig_len)

        if type(ipv6.data) == dpkt.icmp6.ICMP6:
            icmp_num += 1
            icmp_size += orig_len
        elif type(ipv6.data) == dpkt.udp.UDP:
            udp_num += 1
            udp_size += orig_len
            udp_size_list.append(orig_len)

        elif type(ipv6.data) == dpkt.tcp.TCP:
            tcp_num += 1
            tcp_size += orig_len
            tcp_size_list.append(orig_len)

            tcp = ipv6.data
            tcp_header_size_list.append(tcp.off*4)
        else:
            transport_other_num += 1
            transport_other_size += orig_len
    else:
        network_other_num += 1
        network_other_size += orig_len

print "Ethernet: " + str(eth_num) + ", " + str(eth_size) + ", " + str(float(eth_num) / total_num * 100)

print "ARP: " + str(arp_num) + ", " + str(arp_size) + ", " + str(float(arp_num) / total_num * 100)
print "IPV4: " + str(ip_num) + ", " + str(ip_size) + ", " + str(float(ip_num) / total_num * 100)
print "IPV6: " + str(ipv6_num) + ", " + str(ipv6_size) + ", " + str(float(ipv6_num) / total_num * 100)
print "ICMP: " + str(icmp_num) + ", " + str(icmp_size) + ", " + str(float(icmp_num) / total_num * 100)
print "Other Network Layer Protocol: " + str(network_other_num) + ", " + str(network_other_size) + ", " + str(float(network_other_num) / total_num * 100)

all_ip_num = ip_num + ipv6_num
print "TCP: " + str(tcp_num) + ", " + str(tcp_size) + ", " + str(float(tcp_num) / all_ip_num * 100)
print "UDP: " + str(udp_num) + ", " + str(udp_size) + ", " + str(float(udp_num) / all_ip_num * 100)
print "Other Transport Layer Protocol: " + str(transport_other_num) + ", " + str(transport_other_size) + ", " + str(float(transport_other_num) / all_ip_num * 100)

library.plot_cdf(size_list, title="All Packets size", xlabel="log2(size)")
library.plot_cdf(tcp_size_list, title="TCP Packets size", xlabel="log2(size)")
library.plot_cdf(udp_size_list, title="UDP Packets size", xlabel="log2(size)")
library.plot_cdf(ip_size_list, title="IP Packets size", xlabel="log2(size)")
library.plot_cdf(non_ip_size_list, title="Non-IP Packets size", xlabel="log2(size)")


library.plot_cdf([8] * udp_num, title="UDP Headers size", xlabel="size", logarithmic=False)
library.plot_cdf(tcp_header_size_list, title="TCP Headers size", xlabel="size", logarithmic=False)
library.plot_cdf(ip_header_size_list, title="IP Headers size", xlabel="size", logarithmic=False)

