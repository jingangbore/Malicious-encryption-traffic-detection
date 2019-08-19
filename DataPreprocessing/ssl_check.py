from scapy.layers.ssl_tls import *
from scapy.utils import rdpcap
import scapy.all as scapy
import json
import time

check_dic = {}
length = 0


def processCap(fileName, filename2):
    print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    rawTuple_read = open(filename2, "r")
    rawTuple_dic = json.load(rawTuple_read)
    #print("CCCCCCCC")
    global check_dic
    global length
    myreader = scapy.PcapReader(fileName)
    #pkts = scapy.rdpcap(fileName)
    for key in rawTuple_dic:
        dic_ = {}
        dic_["client_sessionID"] = None
        dic_["server_sessionID"] = None
        dic_["sessionID_eq"] = None
        dic_["ssl_state"] = rawTuple_dic[key]["ssl_dic"]["sslConnection"]
        dic_["conn_state"] = rawTuple_dic[key]["conn_dic"]["connectionState"]
        dic_["certificate"] = "F"
        dic_["serverKey"] = "F"
        dic_["serverChangeCipherSpec"] = "F"
        check_dic[key] = dic_
    print("************************************************")
    #only process client hello packet
    #for pkt in pkts:
    i = 0
    while True:
        try:
            pkt = myreader.read_packet()
            if pkt is None:
                break
            # i = i + 1
            # print(i)
            if pkt.haslayer("IP"):
                srcIP = pkt["IP"].src
                dstIP = pkt["IP"].dst
                if srcIP == "10.0.2.15":
                    if pkt.haslayer("TCP"):
                        sport = pkt["TCP"].sport
                        dport = pkt["TCP"].dport
                        key = srcIP + "/" + str(sport) + "/" + dstIP + "/" + str(dport)
                        if pkt.haslayer(TLSClientHello):
                            clienthello = pkt.getlayer(TLSClientHello)
                            id_length = clienthello.session_id_length
                            if id_length != 0:
                                check_dic[key]["client_sessionID"] = clienthello.session_id
                elif dstIP == "10.0.2.15":
                    srcIP = pkt["IP"].src
                    dstIP = pkt["IP"].dst
                    if dstIP == "10.0.2.15":
                        if pkt.haslayer(TCP):
                            sport = pkt["TCP"].sport
                            dport = pkt["TCP"].dport
                            key = dstIP + "/" + str(dport) + "/" + srcIP + "/" + str(sport)
                            if pkt.haslayer(TLSRecord):
                                layer1 = pkt.getlayer(TLSCiphertext)
                                layer1.display()
                                # print(layer2)
                                print("AAAAA")
                                handshakes = pkt.getlayer(TLSHandshakes)
                                for handshake in handshakes:
                                    if handshake.haslayer(TLSServerHello):
                                        print("aaa")
                                        serverhello = pkt.getlayer(TLSServerHello)
                                        id_length = serverhello.session_id_length
                                        if id_length != 0:
                                            check_dic[key]["server_sessionID"] = serverhello.session_id
                                    elif pkt.haslayer(TLSCertificate):
                                        print("bbbb")
                                        check_dic[key]["certificate"] = "T"
                                    elif pkt.haslayer(TLSServerKeyExchange):
                                        print("cccccccc")
                                        check_dic[key]["serverKey"] = "T"
                                    elif pkt.haslayer(TLSChangeCipherSpec):
                                        check_dic[key]["serverChangeCipherSpec"] = "T"
                                    else:
                                        pass

                else:
                    pass
        except:
            break
    # print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
    # for key in check_dic:
    #     length += 1
    #     if check_dic[key]["client_sessionID"] != None and check_dic[key]["server_sessionID"] != None:
    #         if check_dic[key]["client_sessionID"] == check_dic[key]["server_sessionID"]:
    #             check_dic[key]["sessionID_eq"] = "T"
    #case1
    # num_true_ssl = 0
    # num = 0
    # print(length)
    # num_cert = 0
    # num_serverkey = 0
    # num_changeCipher = 0
    # num_client_none = 0
    # for key in check_dic:
    #     if check_dic[key]["ssl_state"] == "T":
    #         num_true_ssl += 1
    #         if check_dic[key]["certificate"] == "T":
    #             num_cert += 1
    #         if check_dic[key]["serverKey"] == "T":
    #             num_serverkey += 1
    #         if check_dic[key]["serverChangeCipherSpec"] == "T":
    #             num_changeCipher += 1
    #         if check_dic[key]["client_sessionID"] == None :
    #             num_client_none += 1
    #             if check_dic[key]["server_sessionID"] == None:
    #                 num += 1
    #         else:
    #             if check_dic[key]["server_sessionID"] != None:
    #                 print(check_dic[key]["sessionID_eq"])
    #     else:
    #         print(">>>>>>>>>>>>")
    #         print(check_dic[key]["client_sessionID"])
    #         print(check_dic[key]["server_sessionID"])
    # print(num_true_ssl)
    # print("num_cert")
    # print(num_cert)
    # print("num_serverkey")
    # print(num_serverkey)
    # print("num_changeCipher")
    # print(num_changeCipher)
    # print("-----------------")
    # print(num_client_none)
    # print(num)

if __name__ == '__main__':
    rawTuple_file = "Datasets/CTU-Normal-27/bro/result_rawTuple.json"
    pcap_file = "Datasets/CTU-Normal-27/456.pcap"
    processCap(pcap_file, rawTuple_file)

