# import numpy
# file = open("Datasets/X_train.txt", "r")
# list = file.readlines()
# lists = []
#
# for fields in list:
#     if not fields.startswith(" "):
#         fields = fields.strip()
#         fields = fields.strip("[]")
#         fields = fields.split(",")
#         lists.append(fields)
#
# arr = numpy.array(lists)
# arr = arr.astype(float)
# #print(arr)
# [rows, cols] = arr.shape
# print(rows, cols)
#
# num = 0
# # for i in arr[:,27]:
# #     if i == 0:
# #         num += num
#
# for i in range(cols):
#     k = 0
#     for j in range(rows):
#         if arr[j, i] == -1.0:
#             k += 1
#     print(k/rows)
#
#
# # print(k_/rows)
#
#
#
# print(num/rows)

d = {'10.3': 5, '50.2': 3, '0.1': 4}
d = sorted(d.items(), key=lambda x: x[0])
print(d)

