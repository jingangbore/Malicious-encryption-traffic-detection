
import numpy as np
from matplotlib import pyplot as plt
from matplotlib.colors import ListedColormap
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.datasets import make_moons, make_circles, make_classification
from sklearn.neural_network import MLPClassifier, MLPRegressor
from Model.Get_normalize_data import get_all_data
from Model.DetectionMethods import detect_with_cross_validation, detect
import xgboost

##################
## Best Result: 0.81449525453 with MLPClassifier(solver='adam', alpha=1e-05, random_state=1)
##################


# final_path = "Final_Experiment\\DividedData\\" + "features_parts\\"
# final_path = "Final_Experiment\\DividedData\\" + "data_model_1\\"
# final_path = "Final_Experiment\\DividedData\\" + "cert_data_model\\"
data_path = "data/"

"""
Read data model 2
"""
# malware_X_train = Get_normalize_data.get_data_from_file(final_path, 'malware_X_train.txt')
# malware_y_train = Get_normalize_data.get_labels_from_file(final_path, 'malware_y_train.txt')
#
# normal_X_train = Get_normalize_data.get_data_from_file(final_path, 'normal_X_train.txt')
# normal_y_train = Get_normalize_data.get_labels_from_file(final_path, 'normal_y_train.txt')
#
# X_test_ = Get_normalize_data.get_data_from_file(final_path, 'X_test.txt')
# y_test_ = Get_normalize_data.get_labels_from_file(final_path, 'y_test.txt')
#
# X = malware_X_train + normal_X_train + X_test_
# y = malware_y_train + normal_y_train + y_test_
# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.2)

"""
Read data model 1
"""
X_train, X_test, y_train, y_test = get_all_data(data_path)




clf = MLPClassifier(solver='adam', alpha=1e-05, random_state=1)


"""
Crossvalidation
"""
detect_with_cross_validation(clf, X_train, y_train)

"""
Learning
"""
clf.fit(X_train, y_train)

"""
Detect
"""
detect(clf, X_test, y_test)

# score = clf.score(X_test, y_test)
# print score


# # iterate over classifiers
# for clf in classifiers:
#     # ax = plt.subplot(len(datasets), len(classifiers) + 1, i)
#     clf.fit(X_train, y_train)
#     score = clf.score(X_test, y_test)
#     # clf.fit(X, y)
#     # score = clf.score(X_test_, y_test_)
#     print score


