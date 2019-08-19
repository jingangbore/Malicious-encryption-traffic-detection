normal = "../Datasets/concat_normal_46.txt"
attack = "../Datasets/concat_malware_46.txt"
data_all = "../Datasets/data_all_46.txt"
normal_read = open(normal, "r")
attack_read = open(attack, "r")
data_write = open(data_all, "w")
while True:
    line = normal_read.readline()
    if not line or line.startswith(" "):
        break
    data_write.write(line)
normal_read.close()

while True:
    line = attack_read.readline()
    if not line or line.startswith(" "):
        break
    data_write.write(line)
attack_read.close()
data_write.close()