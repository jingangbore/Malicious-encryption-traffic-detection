import numpy as np
from Model.Get_normalize_data import get_all_data
data_path = "data/"

"""
Load Data
"""
X_train, X_test, y_train, y_test = get_all_data(data_path)

np_X_train, np_X_test, np_y_train, np_y_test = np.array(X_train), np.array(X_test), np.array(y_train), np.array(y_test)

[rows, cols] = np_X_test.shape
print(rows, cols)
for i in range(rows):
    for j in range(cols):
        if np_X_test[i, j] < -1:
            print(np_X_test[i, j])
print("**************************************")

