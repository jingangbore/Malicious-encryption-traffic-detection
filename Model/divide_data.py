"""
!!! Dividing data for NON-BALANCED data !!!
Divide data from conn_result.txt to payload data (without conn_tuple) and save again.
It divides normal data to training and testing data and then same with Malware.
"""
from sklearn.model_selection import train_test_split
from sklearn.utils import shuffle

def normalize_data(data):
    for i in range(0, len(data[0])):
        max = 0
        for j in range(len(data)):
            if abs(max) < abs(data[j][i]):
                max = abs(data[j][i])
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


"""
----------------------------------------------
--------- Beginning of code ------------------
----------------------------------------------
"""
# Destination path.
source_path = "data/data_all_46.txt"
dst_path = "data/"
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


X = []
Y = []

malwares = 0
normals = 0
for line in all_tuples:
    split = line.split(space)
    label = split[46] # connection data model
    # label = split[7] # certificate data model

    # print label
    number_label = -1
    check_value = 0
    if '1' in label:
        number_label = 1
        malwares += 1
    else:
        number_label = 0
        normals += 1

    temp = []
    for i in range(0, 46):
        temp.append(float(split[i]))
    X.append(temp)
    Y.append(number_label)

# normalize X
norm_X = normalize_data(X)
print("Malwares:", str(malwares))
print("Normals:", str(normals))


# Divide normX and y to malware and normal.
norm_X_malware = []
Y_malware = []
norm_X_normal = []
Y_normal = []
for i in range(0, len(Y)):
    if Y[i] == 1:
        norm_X_malware.append(norm_X[i])
        Y_malware.append(Y[i])
    else:
        norm_X_normal.append(norm_X[i])
        Y_normal.append(Y[i])




# split data by sklearn library
# Split Malware data.
malware_X_train, malware_X_test, malware_Y_train, malware_Y_test = train_test_split(norm_X_malware, Y_malware, test_size=.20, random_state=35)
# Split Normal data.
normal_X_train, normal_X_test, normal_Y_train, normal_Y_test = train_test_split(norm_X_normal, Y_normal, test_size=.20, random_state=42)


# Merge normal and malware train data
X_train = malware_X_train + normal_X_train
Y_train = malware_Y_train + normal_Y_train
# Merge normal and malware test data
X_test = malware_X_test + normal_X_test
Y_test = malware_Y_test + normal_Y_test


X_train, Y_train = shuffle(X_train, Y_train, random_state=43)
X_test, Y_test = shuffle(X_test, Y_test, random_state=101)

# Write train data
write_to_file('X_train_46.txt', X_train)
write_to_file('Y_train_46.txt', Y_train)

# Write test data
write_to_file('X_test.txt_46', X_test)
write_to_file('Y_test.txt_46', Y_test)