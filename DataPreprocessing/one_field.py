import re
import json
import sys
# in_file = "../Datasets/X_train.txt"
# in_read = open(in_file, "r")
# space = "\t"
# sum = 0
# num = 0
# while True:
#     line = in_read.readline()
#     if not line:
#         break
#     if line.startswith(' '):
#         continue
#
#     elements = line.split(space)
#     for i in range(0, 28):
#         if float(elements[i]) < -1.0:
#             # sum += 1
#             print(elements[i])
#             # if i == 10:
#             #     num += 1
#     #print(x_element)
# # print(num/sum)
# in_read.close()


# in_file_ssl = "../Datasets/CTU-Malware-Capture-Botnet-42/bro/ssl.log"
# ssl_read = open(in_file_ssl, "r")
# space = "\t"
#
# while True:
#     line = ssl_read.readline()
#     if not line:
#         break
#     if line.startswith("#") or line.startswith(" "):
#         continue
#     elements = line.split(space)
#     element = elements[9]
#     if len(re.findall(r'\d+\.\d+\.\d+\.\d+', element)) != 0:
#         print(len(element))
# ssl_read.close()


