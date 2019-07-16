import dpkt
import modified_pcap
import library
import pickle
import matplotlib.pyplot as plt

ALPHA = 0.125
# make sure to run the flow.py first
binary_file = open('host_pairs',mode='rb')
host_pairs = pickle.load(binary_file)
binary_file.close()

def func1(flows, title):
    a2b_tuples = []
    b2a_tuples = []

    host_a = flows[0].packets[0].ip_src
    host_b = flows[0].packets[0].ip_dst
    for flow in flows:

        # host a is waiting for ACK packets with these ack number
        # a send time of -1 means this ACK cannot be used to calculate RTT
        a_waiting_ack_sendts_dict = {}
        a2b_srtt = -1
        a2b_srtts = []

        b_waiting_ack_sendts_dict = {}
        b2a_srtt = -1
        b2a_srtts = []
        for packet in flow.packets:
            waiting_ack = (packet.seq + packet.data_size) % (2 ** 32 - 1)
            if library.SYN in packet.flags or library.FIN in packet.flags:
                waiting_ack += 1
                if packet.data_size > 0:
                    print "SYN, FIN packet with payload"

            # if the waiting_ack is already in the dict, an packet before this packet
            # is also waiting for that ack, this is a resend packet, its rtt is invalid
            if packet.ip_src == host_a:
                if waiting_ack in a_waiting_ack_sendts_dict:
                    a_waiting_ack_sendts_dict[waiting_ack] = -1
                else:
                    a_waiting_ack_sendts_dict[waiting_ack] = packet.ts
            else:
                if waiting_ack in b_waiting_ack_sendts_dict:
                    b_waiting_ack_sendts_dict[waiting_ack] = -1
                else:
                    b_waiting_ack_sendts_dict[waiting_ack] = packet.ts

            # if ip_dst == host_a, this is an ACK packet for a
            if packet.ip_dst == host_a:
                if library.ACK in packet.flags:
                    if packet.ack not in a_waiting_ack_sendts_dict:
                        print "Possible error!!!! TCP ACKed unseen segment"
                        print packet
                    else:
                        sendts = a_waiting_ack_sendts_dict[packet.ack]
                        # check if this is a valid ack for rtt estimation
                        if sendts != -1:
                            rtt = packet.ts - sendts
                            if a2b_srtt == -1:
                                a2b_srtt = rtt
                            else:
                                a2b_srtt = (1 - ALPHA) * a2b_srtt + ALPHA * rtt
                            a2b_srtts.append(a2b_srtt)
                            # Any ack packet with same ack number should be invalid
                            a_waiting_ack_sendts_dict[packet.ack] = -1
            else:
                if library.ACK in packet.flags:
                    if packet.ack not in b_waiting_ack_sendts_dict:
                        print "Possible error!!!! TCP ACKed unseen segment"
                        print packet
                    else:
                        sendts = b_waiting_ack_sendts_dict[packet.ack]
                        # check if this is a valid ack for rtt estimation
                        if sendts != -1:
                            rtt = packet.ts - sendts
                            if b2a_srtt == -1:
                                b2a_srtt = rtt
                            else:
                                b2a_srtt = (1 - ALPHA) * b2a_srtt + ALPHA * rtt
                            b2a_srtts.append(b2a_srtt)
                            # Any ack packet with same ack number should be invalid
                            b_waiting_ack_sendts_dict[packet.ack] = -1

        if len(a2b_srtts):
            a2b_median = a2b_srtts[(len(a2b_srtts) - 1) / 2]
            a2b_tuples.append((flow.start, a2b_median))
            # if  not len(b2a_srtts):
            #     print a2b_median
        # else:
        #     print "==============a2b 0==============="
        #     print flow.packets

        if len(b2a_srtts):
            b2a_median = b2a_srtts[(len(b2a_srtts) - 1) / 2]
            b2a_tuples.append((flow.start, b2a_median))
        # else:
        #     print "==============b2a 0==============="
        #     print flow.packets

    # sort list of tuples base on time, unzip into seperate lists
    a2b_tuples.sort(key=lambda x: x[0])
    b2a_tuples.sort(key=lambda x: x[0])
    a2b_times, a2b_representative_rtts = map(list, zip(*a2b_tuples))
    b2a_times, b2a_representative_rtts = map(list, zip(*b2a_tuples))
    # convert times to relative times of the earliest start time
    a2b_times = [time - min(a2b_times) for time in a2b_times]
    b2a_times = [time - min(b2a_times) for time in b2a_times]

    # print len(a2b_representative_rtts)
    plt.plot(a2b_times, a2b_representative_rtts)
    plt.title(host_a + "->" + host_b + ": RTT")
    plt.ylabel("Representative RTT(second)")
    plt.xlabel("Start Time(second)")
    plt.grid()
    plt.savefig("graphs/" + title.replace(" ", "_") + "-a2b" + ".png")
    plt.show()

    # print len(b2a_representative_rtts)
    plt.plot(b2a_times, b2a_representative_rtts)
    plt.title(host_b + "->" + host_a + ": RTT")
    plt.ylabel("Representative RTT(second)")
    plt.xlabel("Start Time(second)")
    plt.grid()
    plt.savefig("graphs/" + title.replace(" ", "_") + "-b2a" + ".png")
    plt.show()

# for flows in host_pairs:
#     host_a = flows[0].packets[0].ip_src
#     host_b = flows[0].packets[0].ip_dst
#     hosts= {host_a,host_b}
#     print hosts
#     print len(flows)
#     total = 0
#     for flow in flows:
#         total += len(flow.packets)
#         for packet in flow.packets:
#             if packet.ip_dst not in hosts or packet.ip_src not in hosts:
#                 print packet
#     print total
# print "Sanity check done"

for i in range(len(host_pairs)):
    func1(host_pairs[i], "Top 3 Pair of Hosts " + str(i+1))
