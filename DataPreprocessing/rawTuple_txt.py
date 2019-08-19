# -*- coding: utf-8 -*-
import json
import time

conn_file = "../Datasets/CTU-Normal-31/bro/conn.log"
ssl_file = "../Datasets/CTU-Normal-31/bro/ssl.log"
x509_file = "../Datasets/CTU-Normal-31/bro/x509.log"
result_file_raw = "../Datasets/CTU-Normal-31/bro/result_rawTuple_txt.json"

space = "\t"
num = 0
conn_dic = {}
x509_dic = {}
tri_dic = {}

with open(conn_file, 'r') as conn_read:
    while True:
        line = conn_read.readline()
        if not line:
            break
        if line.startswith('#') or line.startswith(' '):
            continue
        try:
            uid = line.split(space)[1]
            conn_dic[uid] = line
        except:
            print(line)

with open(x509_file, 'r') as x509_read:
    while True:
        line = x509_read.readline()
        if not line:
            break
        if line.startswith('#') or line.startswith(' '):
            continue
        certID = line.split(space)[1]
        x509_dic[certID] = line


with open(ssl_file, 'r') as ssl_read:
    while True:
        # 整行读取数据
        line = ssl_read.readline()
        if not line:
            break
        if line.startswith('#') or line.startswith(' '):
            continue
        tuple_dic = {}
        ssl_elements = line.split(space)
        uid = ssl_elements[1]
        certID = ssl_elements[14].split(",")[0]
        try:
            conn_line = conn_dic[uid]
        except:
            num += 1
            print("Error in conn")

        conn_elements = conn_line.split(space)
        srcIP = conn_elements[2]
        srcPort = conn_elements[3]
        dstIP = conn_elements[4]
        dstPort = conn_elements[5]
        protocol = conn_elements[6]
        key = srcIP + "/" + srcPort + "/" + dstIP + "/" + dstPort + "/" + protocol + "/" + uid

        if certID != "-":
            x509_line = x509_dic[certID]
        else:
            x509_line = None
        tuple_dic["conn"] = conn_line
        tuple_dic["ssl"] = line
        tuple_dic["x509"] = x509_line
        tri_dic[key] = tuple_dic

with open(result_file_raw, 'w') as result_file:
    json.dump(tri_dic, result_file, indent=2)
print(num)
conn_read.close()
x509_read.close()
ssl_read.close()
result_file.close()
