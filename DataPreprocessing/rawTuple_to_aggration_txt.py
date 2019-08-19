import json
import time

rawTuple_file = "../Datasets/CTU-Normal-31/bro/result_rawTuple_txt.json"
aggration_file = "../Datasets/CTU-Normal-31/bro/result_aggration_txt.json"
conn_file = "../Datasets/CTU-Normal-31/bro/conn.log"

victim_list = []  #,"147.32.84.165", "147.32.84.191", "147.32.84.192"  "147.32.84.193", "147.32.84.204", "147.32.84.205", "147.32.84.206", "147.32.84.207", "147.32.84.208", "147.32.84.209"
normal_list = ["10.0.2.15"] #,  ,"147.32.84.170", "147.32.84.134", "147.32.84.164",  "147.32.87.36", "147.32.80.9", "147.32.87.11"
#"147.32.84.170", "147.32.84.134", "147.32.84.164", "147.32.87.36", "147.32.80.9", "147.32.87.11"
rawTuple_read = open(rawTuple_file, "r")
aggration_write = open(aggration_file, "w")
conn_read = open(conn_file, "r")

space = "\t"
aggration_dic = {}
rawTuple_dic = json.load(rawTuple_read)
uid_dic = {}

for key in rawTuple_dic:
    elements = key.split("/")
    srcIP = elements[0]
    dstIP = elements[2]
    dstPort = elements[3]
    protocol = elements[4]
    uid = elements[5]
    newKey = srcIP + "/" + dstIP + "/" + dstPort + "/" + protocol
    label = " "
    try:
        if aggration_dic[newKey]:
            tmp_dic["tuple_list"].append(rawTuple_dic[key])
            uid_dic[uid] = ""
    except:
        if srcIP in normal_list:
            label = "normal"
        elif srcIP in victim_list:
            label = "malware"
        else:
            pass
        if label in ["normal", "malware"]:
            tmp_dic = {}
            tuple_list = []
            tuple_list.append(rawTuple_dic[key])
            tcp_list = []
            tmp_dic["tuple_list"] = tuple_list
            tmp_dic["tcp_list"] = tcp_list
            tmp_dic["label"] = label
            aggration_dic[newKey] = tmp_dic
            uid_dic[uid] = ""
        else:
            pass

while True:
    line = conn_read.readline()
    if not line:
        break
    if line.startswith('#') or line.startswith(' '):
        continue
    try:
        elements = line.split(space)
        uid = elements[1]
        key = elements[2] + "/" + elements[4] + "/" + elements[5] + "/" + elements[6]
        if key in aggration_dic:
            if uid not in uid_dic:
                aggration_dic[key]["tcp_list"].append(line)
    except:
        print(line)

json.dump(aggration_dic, aggration_write, indent=2)

rawTuple_read.close()
aggration_write.close()
conn_read.close()







