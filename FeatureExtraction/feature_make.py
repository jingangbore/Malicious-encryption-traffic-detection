import json
import os

from FeatureExtraction.ConnectionFeatures import ConnectionFeatures


def read_delta_time(time_file):
    file_read = open(time_file, "r")
    delta_time = ""
    line = file_read.readline()
    if line:
        delta_time = line.rstrip()
    file_read.close()
    return delta_time

path = "../Datasets/"
for sub_set in os.listdir(path):
    aggration_file = path + sub_set + "/bro/result_aggration_txt.json"
    result_file = path + sub_set + "/bro/result_46.txt"
    time_file = path + sub_set + "/bro/delta_time.txt"
    aggration_read = open(aggration_file, "r")
    result_write = open(result_file, "w")
    aggration_dic = json.load(aggration_read)
    delta_time = read_delta_time(time_file)
    for key in aggration_dic:
        location_label = sub_set + "-" + key
        feature = ConnectionFeatures(key, aggration_dic[key]["tuple_list"], aggration_dic[key]["tcp_list"],\
                                     aggration_dic[key]["label"], delta_time, location_label)
        line = feature.get_result_line()
        result_write.write(line)
    aggration_read.close()
    result_write.close()











