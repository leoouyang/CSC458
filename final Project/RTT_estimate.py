import dpkt
import modified_pcap
import library
import pickle
import matplotlib.pyplot as plt

ALPHA = 0.125
# make sure to run the flow.py first
binary_file = open('required_flows',mode='rb')
required_flows = pickle.load(binary_file)
binary_file.close()

# print required_flows["packet_number"][0].packets[0].header.seq
# print required_flows["packet_number"][0].packets[0].header.ack
# print len(required_flows["packet_number"][0].packets)
# print len(required_flows["packet_number"][1].packets)
# print len(required_flows["packet_number"][2].packets)
#
# print required_flows["total_byte"][0].total_bytes
# print required_flows["total_byte"][1].total_bytes
# print required_flows["total_byte"][2].total_bytes
#
# print required_flows["duration"][0].end - required_flows["duration"][0].start
# print required_flows["duration"][1].end - required_flows["duration"][1].start
# print required_flows["duration"][2].end - required_flows["duration"][2].start

def func1(flow, title):
    host_a = flow.packets[0].ip_src
    host_b = flow.packets[0].ip_dst

    # host a is waiting for ACK packets with these ack number
    # a send time of -1 means this ACK cannot be used to calculate RTT
    a_waiting_ack_sendts_dict = {}
    a2b_srtt = -1
    a2b_rtts = []
    a2b_srtts = []
    a2b_times = []

    b_waiting_ack_sendts_dict = {}
    b2a_srtt = -1
    b2a_rtts = []
    b2a_srtts = []
    b2a_times = []
    for packet in flow.packets:
        waiting_ack = (packet.seq + packet.data_size)%(2**32-1)
        if library.SYN in packet.flags or library.FIN in packet.flags:
            waiting_ack += 1
            if packet.data_size > 0:
                print "SYN, FIN packet with payload"

        #if the waiting_ack is already in the dict, an packet before this packet
        #is also waiting for that ack, this is a resend packet, its rtt is invalid
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
                        a2b_rtts.append(rtt)
                        if a2b_srtt == -1:
                            a2b_srtt = rtt
                        else:
                            a2b_srtt = (1-ALPHA)*a2b_srtt + ALPHA * rtt
                        a2b_srtts.append(a2b_srtt)
                        a2b_times.append(packet.ts - flow.start)
                        #Any ack packet with same ack number should be invalid
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
                        b2a_rtts.append(rtt)
                        if b2a_srtt == -1:
                            b2a_srtt = rtt
                        else:
                            b2a_srtt = (1 - ALPHA) * b2a_srtt + ALPHA * rtt
                        b2a_srtts.append(b2a_srtt)
                        b2a_times.append(packet.ts - flow.start)
                        # Any ack packet with same ack number should be invalid
                        b_waiting_ack_sendts_dict[packet.ack] = -1
    # print len(rtts)
    # print len(srtts)
    # print len(times)
    # for i in range(0,1000):
    #     print "Record: "+ str(times[i]) + ", " + str(rtts[i]) + ", " + str(srtts[i])

    # plot graph for middle point to A
    plt.plot(b2a_times, b2a_rtts)
    plt.plot(b2a_times, b2a_srtts)
    plt.title(title + "-Middle to A")
    plt.ylabel("RTT(second)")
    plt.xlabel("Time(second)")
    plt.grid()
    plt.savefig("graphs/" + (title+ "-Middle to A").replace(" ", "_") + ".png")
    plt.show()

    # plot graph for middle point to B
    plt.plot(a2b_times, a2b_rtts)
    plt.plot(a2b_times, a2b_srtts)
    plt.title(title + "-Middle to B")
    plt.ylabel("RTT(second)")
    plt.xlabel("Time(second)")
    plt.grid()
    plt.savefig("graphs/" + (title + "-Middle to B").replace(" ", "_") + ".png")
    plt.show()

print len(required_flows["packet_number"][2].packets)
for i in range(0,3):
    print "===========================" + str(i) + "==========================="
    func1(required_flows["packet_number"][i], "Largest Packet Number Flow " + str(i+1))

for i in range(0,3):
    print "===========================" + str(i) + "==========================="
    func1(required_flows["total_byte"][i], "Largest Total Byte Flow " + str(i+1))

for i in range(0,3):
    print "===========================" + str(i) + "==========================="
    func1(required_flows["duration"][i], "Longest duration Flow " + str(i+1))
