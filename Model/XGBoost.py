"""
https://github.com/frenky-strasak/My_bachelor_thesis
"""

from Model.Get_normalize_data import get_all_data
from Model.DetectionMethods import detect_with_cross_validation, detect
from xgboost import XGBClassifier
import numpy as np
from matplotlib import pyplot
from  sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score
from sklearn.model_selection import StratifiedKFold
##################
## Best Result: 0.909404659189 with datamodel 2
##################


# final_path = "Final_Experiment\\DividedData\\" + "data_model_1\\"
data_path = "data/"

"""
Load Data
"""
X_train, X_test, y_train, y_test = get_all_data(data_path)

np_X_train, np_X_test, np_y_train, np_y_test = np.array(X_train), np.array(X_test), np.array(y_train), np.array(y_test)

"""
Define model
"""
# XGBoost 1
# binary:logistic - logistic regression for binary classification, output probability
model = XGBClassifier(learning_rate=0.1,
                      n_estimators=1600,
                      max_depth=10,
                      min_child_weight=1,
                      gamma=0,
                      subsample=0.8,
                      colsample_bytree=0.8,
                      objective='binary:logistic',
                      nthread=4,
                      scale_pos_weight=1,
                      seed=3)

# XGBoost 2
# title = "Learning Curves ( XGBoost s)"
# model = XGBClassifier(
#     learning_rate=0.1,
#     n_estimators=1000,
#     max_depth=3,
#     min_child_weight=5,
#     gamma=0.1,
#     subsample=0.8,
#     colsample_bytree=0.8,
#     objective='binary:logistic',
#     nthread=4,
#     scale_pos_weight=1,
#     seed=27)

"""
Crossvalidation
"""
detect_with_cross_validation(model, np_X_train, np_y_train)

"""
Detect model
"""

model.fit(np_X_train, np_y_train)
detect(model, np_X_test, np_y_test)

# pyplot.bar(range(len(model.feature_importances_)), model.feature_importances_)
# pyplot.show()

# param = {
#     'n_estimators': [1300, 1400, 1500, 1600, 1700, 1800], #[600, 700, 800, 900, 950, 1000, 1050, 1100, 1150, 1200],
#     'learning_rate': [0.1],
#     'max_depth': [10],
#     'min_child_weight': [1],
#     'gamma': [0],
#     'subsample': [0.8],
#     'colsample_bytree': [0.8],
#     'objective': ['binary:logistic'],
#     'nthread': [4],
#     'scale_pos_weight': [1],
#     'seed': [3]
# }
# kflod = StratifiedKFold(n_splits=10)
# grid_search = GridSearchCV(estimator=model, param_grid=param, scoring='accuracy', cv=kflod)
# grid_result = grid_search.fit(np_X_train, np_y_train)
# print("Best: %f using %s" % (grid_result.best_score_, grid_search.best_params_))
# # print("Best params:")
# # print(grid_search.best_params_)
# means = grid_result.cv_results_['mean_test_score']
# params = grid_result.cv_results_['params']
# for mean, param in zip(means, params):
#     print("%f  with:   %r" % (mean, param))
