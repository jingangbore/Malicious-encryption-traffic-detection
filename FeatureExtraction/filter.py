#验证原文是不是过滤了只有一个ssl记录的样本
import os
import json
if __name__ == '__main__':
    sum = 0
    # save_file = "../Datasets/concat_malware.txt"
    # save_write = open(save_file, "w")
    path = "../Datasets/"
    for sub_set in os.listdir(path):
        if "CTU-" in sub_set:
            path_ = path + sub_set + "/bro"
            files = os.listdir(path_)
            #print(files)
            if "result_aggration_txt.json" in files:
                file = path_ + "/result_aggration_txt.json"
                print(file)
                try:
                    #save_write.write("****************" + file + "\n")
                    aggration_read = open(file, "r")
                    aggration_dic = json.load(aggration_read)
                    for key in aggration_dic:
                        if len(aggration_dic[key]["tuple_list"]) >= 2:
                            sum += 1
                    aggration_read.close()
                except IOError:
                    print("Error in open ", file)
            else:
                print("Error in ", sub_set)
                break
        else:
            pass
    print(sum)
