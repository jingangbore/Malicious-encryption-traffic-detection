"""
https://github.com/frenky-strasak/My_bachelor_thesis
"""

from Model.Get_normalize_data import get_all_data
from Model.DetectionMethods import detect_with_cross_validation, detect
from sklearn.ensemble import GradientBoostingClassifier
from  sklearn.model_selection import GridSearchCV
from sklearn.metrics import accuracy_score
from sklearn.model_selection import StratifiedKFold
from matplotlib import pyplot


"""
Read data model 1
"""
# final_path = "Final_Experiment\\DividedData\\" + "cert_data_model\\"
# final_path = "/home/frenky/PycharmProjects/HTTPSDetector/MachineLearning/data_model/"
data_path = "data/"
X_train, X_test, Y_train, Y_test = get_all_data(data_path)

"""
Define model
"""
# model = RandomForestClassifier()
model = GradientBoostingClassifier(learning_rate=0.1, n_estimators=1300)

"""
Crossvalidation
"""
detect_with_cross_validation(model, X_train, Y_train)

"""
Detecting
"""
model.fit(X_train, Y_train)
detect(model, X_test, Y_test)


# param = {
#     'n_estimators': [500, 600, 700, 800, 900, 1000, 1100, 1200, 1300, 1400]
# }
# kflod = StratifiedKFold(n_splits=10)
# grid_search = GridSearchCV(estimator=model, param_grid=param, scoring='accuracy', cv=kflod)
# grid_result = grid_search.fit(X_train, Y_train)
# print("Best: %f using %s" % (grid_result.best_score_, grid_search.best_params_))
#
# means = grid_result.cv_results_['mean_test_score']
# params = grid_result.cv_results_['params']
# for mean, param in zip(means,params):
#     print("%f  with:   %r" % (mean, param))

# pyplot.bar(range(len(model.feature_importances_)), model.feature_importances_)
# pyplot.show()