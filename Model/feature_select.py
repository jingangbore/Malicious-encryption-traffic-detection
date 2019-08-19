import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.feature_selection import SelectFromModel
from sklearn.ensemble import GradientBoostingClassifier
from Model.Get_normalize_data import get_data_from_file, get_labels_from_file

dst_path = "data/"
def normalize_data(data):
    for i in range(0, len(data[0])):
        max = 0
        for j in range(len(data)):
            if max < data[j][i]:
                max = data[j][i]
        if max != 0:
            for j in range(len(data)):
                if data[j][i] != -1:
                    data[j][i] = data[j][i] / float(max)
    return data

def write_to_file(file_name, data_list):
    index = 0
    with open(dst_path + file_name, 'w') as f:
        for dataline in data_list:
            f.write(str(dataline) + "\n")
            index += 1
    f.close()
    print(file_name, "written lines:", str(index))


# source_path = "data/data_all.txt"

# space = "\t"
# # Load all file to array.
# all_tuples = []
# try:
#     with open(source_path) as f:
#     # with open("DividedData\\all_features_2\\malware_connections.txt") as f:
#         while True:
#             line = f.readline()
#             if not line or line.startswith(" "):
#                 break
#             all_tuples.append(line)
#     f.close()
# except:
#     print("Error: No file is avaible.")

#
# X = []
# for line in all_tuples:
#     split = line.split(space)
#
#     temp = []
#     for i in range(0, 28):
#         temp.append(float(split[i]))
#     X.append(temp)
#
# norm_X = normalize_data(X)
#write_to_file('data_all_norm_X.txt', norm_X)
# norm_X_numpy = np.array(norm_X)
#
# [conn, ssl, x509] = np.split(norm_X_numpy, [6, 18], axis=1)
# print(conn.shape)
# data = pd.DataFrame(conn, columns=['1', '2', '3', '4', '5', '6'])#, 'G', 'H', 'I', 'J', 'K', 'L'])
# # 相关性计算
# print(data.corr())
# # 绘图
# fig = pd.plotting.scatter_matrix(data, figsize=(12, 12), c='blue', marker='o', diagonal='', alpha=0.8, range_padding=0.2)
# plt.show()

# Y = []
# for line in all_tuples:
#     split = line.split(space)
#     Y.append(int(split[28]))
# write_to_file('data_all_norm_Y.txt', Y)


# data_path = "data/"
# X = get_data_from_file(data_path, "data_all_norm_X.txt")
# Y = get_labels_from_file(data_path, "data_all_norm_Y.txt")
#
# model = SelectFromModel(GradientBoostingClassifier()).fit_transform(X, Y)






source_path = "data/data_all.txt"

space = "\t"
# Load all file to array.
all_tuples = []
try:
    with open(source_path) as f:
    # with open("DividedData\\all_features_2\\malware_connections.txt") as f:
        while True:
            line = f.readline()
            if not line or line.startswith(" "):
                break
            all_tuples.append(line)
    f.close()
except:
    print("Error: No file is avaible.")
size = len(all_tuples)
print(size)
num = 0
X = []
for line in all_tuples:
    split = line.split(space)
    if float(split[18]) == -1:
        num += 1
    X.append(float(split[18]))
print(num)
print(np.std(X))