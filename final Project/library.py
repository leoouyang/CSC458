import matplotlib.pyplot as plt
import math
import dpkt
import socket
import win_inet_pton

TCP = "tcp"
UDP = "udp"

FIN = 'F'
SYN = 'S'
RST = 'R'
PUSH = 'P'
ACK = 'A'
URG = 'U'
ECE = 'E'
CWR = 'C'


class Packet:
    def __init__(self, ts, size, protocol, ip_src, ip_dst, header, ip_data_size = 0):
        self.ts = ts
        self.size = size
        self.protocol = protocol
        self.header = header
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        if self.protocol == TCP:
            self.flags = self.get_flags()
            self.seq = self.header.seq
            self.ack = self.header.ack
            # in my case, tcp are only used in ipv4
            self.data_size = ip_data_size - self.header.off * 4
        else:
            self.data_size = ip_data_size - 8

    def __str__(self):
        result = "Timestamp: " + str(self.ts) + ", Protocol: " + self.protocol + \
               ", Size: " + str(self.size) + ", " + self.ip_src + ":" + \
               str(self.header.sport) + "->" + self.ip_dst + ":" + str(self.header.dport)
        if self.protocol == TCP:
            result += ", flags: " + self.flags
        return result + "==="

    def __repr__(self):
        return str(self)

    def get_flags(self):
        if self.protocol == TCP:
            flags = self.header.flags
            result = ""
            if flags & dpkt.tcp.TH_FIN:
                result = result + FIN
            if flags & dpkt.tcp.TH_SYN:
                result = result + SYN
            if flags & dpkt.tcp.TH_RST:
                result = result + RST
            if flags & dpkt.tcp.TH_PUSH:
                result = result + PUSH
            if flags & dpkt.tcp.TH_ACK:
                result = result + ACK
            if flags & dpkt.tcp.TH_URG:
                result = result + URG
            if flags & dpkt.tcp.TH_ECE:
                result = result + ECE
            if flags & dpkt.tcp.TH_CWR:
                result = result + CWR
            return result
        else:
            print "UDP doesn't have flags"

class Flow:
    def __init__(self, protocol, packets):
        self.protocol = protocol
        self.packets = packets
        if len(packets) != 0:
            self.total_bytes = 0
            self.total_data = 0
            for pkt in packets:
                self.total_bytes += pkt.size
                self.total_data += pkt.data_size
            self.ip_src = packets[0].ip_src
            self.ip_dst = packets[0].ip_dst
            self.sport = packets[0].header.sport
            self.dport = packets[0].header.dport
            self.start = packets[0].ts
            self.end = packets[-1].ts
            # print max(packets, key=lambda x:x.ts).ts
        else:
            print "packet list should not have a length of 0!!!"

    def get_inter_packet_arrival_times(self):
        result = [0]
        for i in range(1, len(self.packets)):
            cur_packet = self.packets[i]
            prev_packet = self.packets[i-1]
            result.append(cur_packet.ts - prev_packet.ts)
        return result


def plot_cdf(values, title="", xlabel="", logarithmic=True):
    values.sort()
    if len(values) > 50:
        step = len(values) / 50
        y = []
        x = []
        for i in range(0, 50):
            y.append(i*2/100.0)
            if logarithmic:
                x.append(math.log(values[i * step], 2))
            else:
                x.append(values[i * step])

        y.append(1)
        if logarithmic:
            x.append(math.log(values[-1], 2))
        else:
            x.append(values[-1])

        # print x
        # print y
        plt.plot(x, y)
        margin = (x[-1] - x[0]) * 0.05
        plt.axis([x[0] - margin, x[-1] + margin, 0, 1])
        plt.title(title)
        plt.ylabel("Percentage")
        plt.xlabel(xlabel)
        plt.grid()
        plt.savefig("graphs/"+title.replace(" ", "_")+".png")
        plt.show()


def construct_key(ip_src, ip_dst, sport, dport):
    if ip_src > ip_dst:
        return ip_src + ":" + str(sport) + "-" + ip_dst + ":" + str(dport)
    else:
        return ip_dst + ":" + str(dport) + "-" + ip_src + ":" + str(sport)


def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return win_inet_pton.inet_ntop(socket.AF_INET, inet)
    except socket.error:
        return win_inet_pton.inet_ntop(socket.AF_INET6, inet)

if __name__ == "__main__":

    list = []
    for i in range(100):
        list.append(i)

    plot_cdf(list, False)
