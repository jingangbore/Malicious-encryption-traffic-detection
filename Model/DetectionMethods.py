from sklearn import svm
import numpy as np
from sklearn.model_selection import cross_val_score
from sklearn.model_selection import KFold
from sklearn.metrics import confusion_matrix


def detect(model, test_data, test_labels):

    # train_data = np.array(train_data).reshape((1, -1))
    # test_data = np.array(test_data).reshape((1, -1))

    # print train_data

    # clf = svm.SVC(gamma=0.001, C=100)
    # clf = svm.SVC(kernel='linear', C=1)
    # kernels = ['linear', 'poly', 'rbf']
    # clf = svm.SVC(kernel=kernels[2], C=100, gamma=1)
    # X,y = train_data, train_labels
    # clf.fit(X,y)


    results = (model.predict(test_data))

    num = len(test_labels)
    """
    Print and evaluate results.
    """
    false_positive = 0  # 1 - 0
    true_positive = 0   # 1 - 1
    false_negative = 0  # 0 - 1
    true_negative = 0   # 0 - 0
    # print "Result more :"
    for i in range(len(test_data)):
        # print results[i], " - ", test_labels[i]
        if results[i] == 1 and test_labels[i] == 0:
            false_positive += 1
        if results[i] == 1 and test_labels[i] == 1:
            true_positive += 1
        if results[i] == 0 and test_labels[i] == 1:
            false_negative += 1
        if results[i] == 0 and test_labels[i] == 0:
            true_negative += 1

    print("----------------------------------")
    print("----- FINAL RESULTS --------------")
    print("----------------------------------")
    print("total is ", str(num))
    print("false positive rate:", str(false_positive/num))
    print("true positive rate:", str(true_positive/num))
    print("false negative rate:", str(false_negative/num))
    print("true negative rate:", str(true_negative/num))
    print("----------------------------------------------")
    print("library detection:", str(model.score(test_data, test_labels)))
    print("good detect:", str((true_negative + true_positive)), str(((true_negative + true_positive) / float(len(test_data)))))
    print("bad detect:", str((false_negative + false_positive)), str(((false_negative + false_positive) / float(len(test_data)))))
    print("All connection:", str(len(test_data)))


def detect_with_cross_validation(model, norm_data, labels):
    scores = cross_val_score(model, norm_data, labels, cv=10)

    print("----------------------------------")
    print("----- CROSSVALIDATION ------------")
    print("----------------------------------")
    print(scores)
    print(np.mean(scores))