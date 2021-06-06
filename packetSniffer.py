import binascii
import socket, sys, struct
import matplotlib.pyplot as plt

# create a network socket using the default constructor




try:
    sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
except socket.error:
    print('Socket could not be created.')
    sys.exit(1)


def analyze_tcp_header(data, iphH):
    packet = struct.unpack("!HHLLBBHHH", data[iph:20+iphH])
    src_port = packet[0]
    dst_port = packet[1]

    return dst_port, src_port


def analyze_udp_header(data, iphH):
    udp_hdr = struct.unpack("!HHHH", data[iph:8+iphH])
    src_port = udp_hdr[0]
    dst_port = udp_hdr[1]
    return dst_port, src_port


HTTP = 0
HTTPS = 0
DNS = 0
OTHER = 0


def upperLevelProto(dPort, sPort):
    global HTTP
    global HTTPS
    global OTHER
    global DNS
    if dPort == 80 or sPort == 80:
        HTTP += 1
    elif dPort == 443 or sPort == 443:
        HTTPS += 1
    elif dPort == 53 or sPort == 53:
        DNS += 1
    else:
        OTHER += 1


def analyze_ip_header(data):
    ip_hdr = struct.unpack("!6H4s4s", data[:20])

    version = ip_hdr[0] >> 12
    ihl = (ip_hdr[0] >> 8) & 0x0f  # 00001111
    tos = ip_hdr[0] & 0x00ff

    length = ip_hdr[1]

    ip_id = ip_hdr[2]

    flags = ip_hdr[3] >> 13
    frag_offset = ip_hdr[3] & 0x1fff

    ip_ttl = ip_hdr[4] >> 8
    ip_protocol = ip_hdr[4] & 0x00ff

    chksum = ip_hdr[5]

    src_addr = socket.inet_ntoa(ip_hdr[6])
    dst_addr = socket.inet_ntoa(ip_hdr[7])

    no_frag = flags >> 1
    more_frag = flags & 0x1
    # Portocol table
    table = {num: name[8:] for name, num in vars(socket).items() if name.startswith("IPPROTO")}
    try:
        proto_name = "(%s)" % table[ip_protocol]
    except:
        proto_name = ""

    print("|=============== IP HEADER ===============|")

    print("\tVersion:\t%hu" % version)
    print("\tIHL:\t\t%hu" % ihl)
    print("\tTOS:\t\t%hu" % tos)
    print("\tID:\t\t%hu" % ip_id)
    print("\tNo Frag:\t%hu" % no_frag)
    print("\tMore frag:\t%hu" % more_frag)
    print("\tOffset:\t\t%hu" % frag_offset)
    print("\tTTL:\t\t%hu" % ip_ttl)
    print("\tNext protocol:\t%hu%s" % (ip_protocol, proto_name))
    print("\tChecksum:\t%hu" % chksum)
    print("\tSource IP:\t%s" % src_addr)
    print("\tDest IP:\t%s" % dst_addr)

    if (ip_protocol == 6):  # TCP magic number
        next_proto = "TCP"
    elif (ip_protocol == 17):  # UDP magic number
        next_proto = "UDP"
    elif (ip_protocol == 1):
        next_proto = "ICMP"
    else:
        next_proto = "OTHER"
    #print(next_proto)
    data_length = length - (ihl * 32) / 8
    print("\tData Length IP:\t%s" % data_length)
    iph_length = ihl * 4
    #dataaa = data[iph_length:]
    #return data, data_length, next_proto
    return no_frag, more_frag, ip_ttl, next_proto, src_addr,dst_addr, data_length, iph_length

def analyze_ether_data(data):
    ip_bool = False
    eth_hdr = struct.unpack("!6s6sH", data[:14])
    protocol = eth_hdr[2] >> 8  # Next Protocol
    if (protocol == 8):  # IPv4 = 0x0800
        ip_bool = True
    dataa = data[14:]
    return dataa, ip_bool


def getProtocolCount(list):
    TCP = 0
    UDP = 0
    ICMP = 0
    OTHERS = 0
    protocols = []
    for elements in list:
        if len(elements) != 4:
            continue
        protocols.append(elements[1])
    for i in protocols:
        if i == "TCP":
            TCP += 1
        elif i == "UDP":
            UDP += 1
        elif i == "ICMP":
            ICMP += 1
        else:
            OTHERS += 1
    return TCP, UDP, ICMP, OTHERS


def sortIP(list):
    ip_quantity = {}
    for element3 in list:
        if len(element3) != 4:
            continue
        if element3[0] not in ip_quantity.keys():
            ip_quantity[element3[0]] = 1
        else:
            ip_quantity[element3[0]] += 1
    sort_orders = sorted(ip_quantity.items(), key=lambda x: x[1], reverse=True)
    return sort_orders


def numberOfFrags(list):
    fragment = 0
    for element2 in list:
        if len(element2) != 4:
            continue
        if element2[3] == 0:
            fragment += 1
    return fragment


def minMaxAvg(list):
    newList = []
    for element4 in list:
        if len(element4) != 4:
            continue
        newList.append(element4[2])
    minimum = min(newList)
    # print(minimum)
    maximum = max(newList)
    # print(maximum)
    average = sum(newList)/len(newList)
    #print(average)
    return minimum, maximum, average


if __name__ == '__main__':
    array = []
    portha = []
    try:
        while True:
            new = []
            portha2 = []
            # raw_data, address = sock.recvfrom(65565)
            sniffed_data = sock.recv(2048)
            dataa, ip_bool = analyze_ether_data(sniffed_data)
            if ip_bool:
                # data, data_length, next_proto = analyze_ip_header(dataa)
                no_frag, more_frag, ip_ttl, proto_name, src_addr,dst_addr, data_length, iph = analyze_ip_header(dataa)
                if proto_name == "TCP":
                    dport, sport = analyze_tcp_header(dataa,iph)
                    portha2.append(sport)
                    portha2.append(dport)
                    #print(port)
                    upperLevelProto(dport, sport)
                if proto_name == "UDP":
                    dport, sport = analyze_udp_header(dataa, iph)
                    portha2.append(sport)
                    portha2.append(dport)
                    #print(port)
                    upperLevelProto(dport, sport)
                new.append(src_addr)
                new.append(proto_name)
                new.append(data_length)
                new.append(no_frag)
            portha.append(portha2)
            array.append(new)
    except KeyboardInterrupt:
        print(" you stopped packet sniffing")
        #print("HTTP :"+ str(HTTP))
        #print("HTTPS :" + str(HTTPS))
        #print("DNS :"+str(DNS))
        #print("others: :" + str(OTHER))

        with open("DATA.txt", 'w') as file:
            TCP, UDP, ICMP, OTHERS = getProtocolCount(array)
            file.write("TCP:" + str(TCP) + "  UDP:" + str(UDP) + "  ICMP:" + str(ICMP) + "    OTHERS:" + str(OTHERS))
            file.write("\n\n")
            FRAG = numberOfFrags(array)
            file.write("Number Of Fragmented Packets: " + str(FRAG))
            file.write("\n\n")
            file.write("HTTP:" + str(HTTP) + " HTTPS: " + str(HTTPS) + " DNS:"+ str(DNS) + "  OTHERS:" + str(OTHER))
            file.write("\n\n")
            minimum, maximum, average = minMaxAvg(array)
            file.write(
                "Minimum Length:" + str(minimum) + "   Maximum Length:" + str(maximum) + "   Average Length:" + str(
                    average))
            file.write("\n\n")
            IP_LIST = sortIP(array)
            for element in IP_LIST:
                file.write(element[0] + "    Total sent packets:" + str(element[1]))
                file.write("\n")
            file.close()

        plt.figure(figsize=(12, 6))
        plt.subplot(331)
        labels1 = "TCP", "UDP", "ICMP", "OTHERS"
        sizes1 = [TCP, UDP, ICMP, OTHERS]
        explode1 = (0, 0, 0, 0)

        plt.pie(sizes1, explode=explode1, labels=labels1, autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')

        """next plot"""
        plt.subplot(332)
        labels2 = "More Frags", "NO Frags"
        sizes2 = [FRAG, TCP + UDP + ICMP + OTHERS - FRAG]
        explode2 = (0, 0)

        plt.pie(sizes2, explode=explode2, labels=labels2, autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')

        """next plot"""
        plt.subplot(333)
        labels2 = "HTTP", "HTTPS", "DNS", "OTHERS"
        sizes2 = [HTTP, HTTPS, DNS, OTHER]
        explode2 = (0, 0, 0, 0)

        plt.pie(sizes2, explode=explode2, labels=labels2, autopct='%1.1f%%', shadow=True, startangle=90)
        plt.axis('equal')

        """next plot"""
        plt.subplot(334)
        x = ['Min', 'Max', 'Avg']
        energy = [minimum, maximum, average]

        x_pos = [i for i, _ in enumerate(x)]

        plt.bar(x_pos, energy, color='yellow')
        plt.ylabel("Length")

        plt.xticks(x_pos, x)

        """next plot"""
        plt.subplot(335)
        ips = []
        vals = []
        rank = 1
        for e in IP_LIST:
            ips.append(rank)
            vals.append(e[1])
            rank += 1
        plt.plot(ips, vals, 'ro')
        plt.xlabel("Ranking")
        plt.ylabel("TSP")
        plt.axis([0, len(IP_LIST), 0, vals[0]])

        plt.show()

        pass



