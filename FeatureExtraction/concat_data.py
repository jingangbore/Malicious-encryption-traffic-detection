import os
if __name__ == '__main__':
    save_file = "../Datasets/concat_malware_46.txt"
    save_write = open(save_file, "w")
    path = "../Datasets/"
    for sub_set in os.listdir(path):
        if "CTU-Malware-Capture-Botnet" in sub_set:
            path_ = path + sub_set + "/bro"
            files = os.listdir(path_)
            #print(files)
            if "result_47.txt" in files:
                file = path_ + "/result_46.txt"
                print(file)
                try:
                    #save_write.write("****************" + file + "\n")
                    with open(file) as f:
                        while True:
                            line = f.readline()
                            if not line:
                                break
                            if line.startswith(' '):
                                continue
                            save_write.write(line)
                    f.close()
                except IOError:
                    print("Error in open ", file)
            else:
                print("Error in ", sub_set)
                break
        else:
            pass