import numpy as np
import re

space = "\t"

#2019/8/18 修正4 16 18 19这4个特征
class ConnectionFeatures(object):
    def __init__(self, key, tuple_list, tcp_list, label, delta_time, sub_set):
        self.key = key
        self.tuple_list = tuple_list
        self.tcp_list = tcp_list
        self.label = label
        self.delta_time = 0
        self.delta_time = delta_time

        self.record_num = 0
        self.cert_dic = {}
        self.cert_length_dic = {}
        self.duration_list = []
        self.origin_bytes_total = 0
        self.destination_bytes_total = 0
        self.origin_pkts_total = 0
        self.destination_pkts_total = 0
        self.established_num = 0
        self.timestamp_list = []
        self._1nd_list = []
        self._2nd_list = []
        self.tls_ssl_num = 0
        self.tls_num = 0
        self.SNI_num = 0
        self.SNI_as_IP_num = 0
        self.SNI_not_as_IP_num = 0
        self.SNI_as_IP = -1
        self.has_cert_num = 0
        self.self_signed_num = 0
        self.certPath_length_list = []
        self.valid_length_list = []
        self.valid_num = 0
        self.valid_ratio_list = []
        self.SANdns_num_list = []
        self.x509_line_num = 0
        self.SNI_in_SANdns_list = []
        self.CN_in_SANdns_list = []



        self.pre_process()

    def pre_process(self):
        self.record_num = len(self.tuple_list) + len(self.tcp_list)
        for item in self.tuple_list:
            ssl_line = item["ssl"]
            ssl_elements = ssl_line.split(space)
            version = ssl_elements[6]
            if "TLS" in version or "SSL" in version:
                self.tls_ssl_num += 1
                if "TLS" in version:
                    self.tls_num += 1
            SNI = ssl_elements[9]
            if SNI != "-":
                self.SNI_num += 1
                if len(re.findall(r'\d+\.\d+\.\d+\.\d+', SNI)) != 0:
                    dstIP = self.key.split("/")[1]
                    if dstIP == SNI:
                        self.SNI_as_IP = 1
                        self.SNI_as_IP_num += 1
                    else:
                        self.SNI_as_IP = 0.5
                        self.SNI_not_as_IP_num += 1

            certPath = ssl_elements[14]
            if certPath == "-":
                self.certPath_length_list.append(0)
            else:
                self.has_cert_num += 1
                cert_uids = certPath.split(",")
                self.certPath_length_list.append(len(cert_uids))

            if 'signed certificate in certificate' in ssl_line:
                self.self_signed_num += 1
            #
            conn_line = item["conn"]
            conn_elements = conn_line.split(space)
            duration = conn_elements[8]
            if duration == "-":
                duration = "0"
            self.duration_list.append(float(duration))
            origin_bytes, destination_bytes = conn_elements[9], conn_elements[10]
            if origin_bytes == "-":
                origin_bytes = "0"
            self.origin_bytes_total += int(origin_bytes)
            if destination_bytes == "-":
                destination_bytes = "0"
            self.destination_bytes_total += int(destination_bytes)
            established_state = conn_elements[11]
            if established_state in ['SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR']:
                self.established_num += 1
            origin_pkts, destination_pkts = conn_elements[16], conn_elements[18]
            if origin_pkts == "-":
                origin_pkts = "0"
            self.origin_pkts_total += int(origin_pkts)
            if destination_pkts == "-":
                destination_pkts = "0"
            self.destination_pkts_total += int(destination_pkts)
            self.timestamp_list.append(float(conn_elements[0]))
            #
            if item["x509"]:
                self.x509_line_num += 1
                x509_elements = item["x509"].split(space)
                cert_sertial, cert_length = x509_elements[3], x509_elements[11]
                try:
                    if self.cert_dic[cert_sertial]:
                        self.cert_dic[cert_sertial] += 1
                except:
                    self.cert_dic[cert_sertial] = 1
                try:
                    if self.cert_length_dic[cert_length]:
                        self.cert_length_dic[cert_length] += 1
                except:
                    self.cert_length_dic[cert_length] = 1
                if x509_elements[6] != "-" and x509_elements[7] != "-":
                    from_, to_ = float(x509_elements[6]), float(x509_elements[7])
                    valid = round((to_ - from_) / (3600 * 24), 2)
                    self.valid_length_list.append(valid)
                    if self.delta_time == "":
                        self.delta_time = "0"
                    timestamp = float(x509_elements[0]) + float(self.delta_time)
                    if (timestamp < to_) and (timestamp > from_):
                        self.valid_num += 1
                    ratio = (timestamp - from_) / (to_ - from_)
                    self.valid_ratio_list.append(ratio)
                if x509_elements[14] is "-":
                    self.SANdns_num_list.append(0)
                else:
                    num = len(x509_elements[14].split(","))
                    self.SANdns_num_list.append(num)
                    if SNI != "-":
                        if SNI in x509_elements[14]:
                            self.SNI_in_SANdns_list.append(1)
                        else:
                            self.SNI_in_SANdns_list.append(0)
                    if x509_elements[4] != "-":
                        CN = x509_elements[4].split(",")[0][3:].replace("*", "")
                        if CN in x509_elements[14]:
                            self.CN_in_SANdns_list.append(1)
                        else:
                            self.CN_in_SANdns_list.append(0)

        for item in self.tcp_list:
            tcp_elements = item.split(space)
            duration = tcp_elements[8]
            if duration == "-":
                duration = "0"
            self.duration_list.append(float(duration))
            origin_bytes, destination_bytes = tcp_elements[9], tcp_elements[10]
            if origin_bytes == "-":
                origin_bytes = "0"
            self.origin_bytes_total += int(origin_bytes)
            if destination_bytes == "-":
                destination_bytes = "0"
            self.destination_bytes_total += int(destination_bytes)
            established_state = tcp_elements[11]
            if established_state in ['SF', 'S1', 'S2', 'S3', 'RSTO', 'RSTR']:
                self.established_num += 1
            origin_pkts, destination_pkts = tcp_elements[16], tcp_elements[18]
            if origin_pkts == "-":
                origin_pkts = "0"
            self.origin_pkts_total += int(origin_pkts)
            if destination_pkts == "-":
                destination_pkts = "0"
            self.destination_pkts_total += int(destination_pkts)
            self.timestamp_list.append(float(tcp_elements[0]))
    #1
    def get_record_num(self):
        return self.record_num
    # 2
    def get_duration_mean(self):
        return np.mean(self.duration_list)
    # 3
    def get_duration_std(self):
        return np.std(self.duration_list)
    # 4
    def get_ratio_duraion_exceed(self):
        duration_max = np.mean(self.duration_list) + np.std(self.duration_list)
        duration_min = np.mean(self.duration_list) - np.std(self.duration_list)
        num = 0
        for duration in self.duration_list:
            if duration > duration_max or duration < duration_min:
                num += 1
        return float(num / self.get_record_num())
    # 5
    def get_origin_bytes(self):
        return self.origin_bytes_total
    # 6
    def get_destination_bytes(self):
        return self.destination_bytes_total
    # 7
    def get_ratio_bytes(self):
        return self.destination_bytes_total/(self.origin_bytes_total+self.destination_bytes_total)
    # 8
    def get_ratio_established(self):
        return float(self.established_num/self.get_record_num())
    # 9
    def get_origin_pkts(self):
        return self.origin_pkts_total
    # 10
    def get_destination_pkts(self):
        return self.destination_pkts_total
    # 11
    def get_2nd_mean(self):
        if self.get_record_num() <= 2:
            return -1
        self.timestamp_list.sort()
        i, j = 1, 1
        while i < self.get_record_num():
            self._1nd_list.append(self.timestamp_list[i] - self.timestamp_list[i - 1])
            i = i + 1
        while j < (self.get_record_num() - 1):
            self._2nd_list.append(self._1nd_list[j] - self._1nd_list[j - 1])
            j = j + 1
        return np.mean(self._2nd_list)
    # 12
    def get_2nd_std(self):
        if self.get_record_num() <= 2:
            return -1
        return np.std(self._2nd_list)
    # 13
    def get_ratio_tcp(self):
        return float(len(self.tcp_list) / self.get_record_num())
    # 14
    def get_ratio_tls(self):
        if self.tls_ssl_num == 0:
            return -1
        return float(self.tls_num / self.tls_ssl_num)
    # 15
    def get_ratio_SNI(self):
        return float(self.SNI_num / len(self.tuple_list))
    # 16
    def get_SNI_as_IP(self):
        if (self.SNI_num != 0) and (self.SNI_as_IP != 0.5) and (self.SNI_as_IP != 1):
            self.SNI_as_IP = 0
        if (self.SNI_as_IP_num != 0) and (self.SNI_not_as_IP_num != 0):
            self.SNI_as_IP = 0.75
        return self.SNI_as_IP
    # 17
    def get_certPath_length_mean(self):
        if self.has_cert_num == 0:
            return -1
        return np.mean(self.certPath_length_list)
    # 18
    def get_ratio_self_signed(self):
        if self.has_cert_num == 0:
            return -1
        return float(self.self_signed_num / len(self.tuple_list))
    # 19
    def get_key_length_mean(self):
        if len(self.cert_length_dic.keys()) == 0:
            return -1
        length, num = 0, 0
        for key in self.cert_length_dic:
            num += int(self.cert_length_dic[key])
            length += int(key) * int(self.cert_length_dic[key])
        return length/num
    # 20
    def get_valid_length_mean(self):
        if len(self.valid_length_list) == 0:
            return -1
        return np.mean(self.valid_length_list)
    # 21
    def get_valid_length_std(self):
        if len(self.valid_length_list) == 0:
            return -1
        return np.std(self.valid_length_list)
    # 22
    def get_ratio_valid(self):
        if len(self.valid_length_list) == 0:
            return -1
        return float(self.valid_num / len(self.valid_length_list))
    # 23
    def get_valid_ratio_mean(self):
        if len(self.valid_ratio_list) == 0:
            return -1
        return np.mean(self.valid_ratio_list)
    # 24
    def get_cert_num(self):
        return len(self.cert_dic.keys())
    # 25
    def get_SANdns_mean(self):
        if self.x509_line_num == 0:
            return -1
        return np.mean(self.SANdns_num_list)
    # 26
    def get_x509_ratio(self):
        return float(self.x509_line_num / len(self.tuple_list))
    # 27
    def get_SNI_in_SANdns(self):
        if len(self.SNI_in_SANdns_list) == 0:
            return -1
        for val in self.SNI_in_SANdns_list:
            if val == 0:
                return 0
        return 1
    # 28
    def get_CN_in_SANdns(self):
        if len(self.CN_in_SANdns_list) == 0:
            return -1
        for val in self.CN_in_SANdns_list:
            if val == 0:
                return 0
        return 1

    def get_label(self):
        if self.label == "malware":
            return 1
        else:
            return 0
    def get_result_line(self):
        return str(self.get_record_num()) + space + str(self.get_duration_mean()) + space + str(self.get_duration_std()) + space + \
               str(self.get_ratio_duraion_exceed()) + space + str(self.get_origin_bytes()) + space + \
               str(self.get_destination_bytes()) + space + str(self.get_ratio_bytes()) + space + \
               str(self.get_ratio_established()) + space + str(self.get_origin_pkts()) + space + \
               str(self.get_destination_pkts()) + space + str(self.get_2nd_mean()) + space + str(self.get_2nd_std()) + space + \
               str(self.get_ratio_tcp()) + space + str(self.get_ratio_tls()) + space + str(self.get_ratio_SNI()) + space + \
               str(self.get_SNI_as_IP()) + space + str(self.get_certPath_length_mean()) + space + \
               str(self.get_ratio_self_signed()) + space + str(self.get_key_length_mean()) + space + \
               str(self.get_valid_length_mean()) + space + str(self.get_valid_length_std()) + space + \
               str(self.get_ratio_valid()) + space + str(self.get_valid_ratio_mean()) + space + str(self.get_cert_num()) + space + \
               str(self.get_SANdns_mean()) + space + str(self.get_x509_ratio()) + space + str(self.get_SNI_in_SANdns()) + space + \
               str(self.get_CN_in_SANdns()) + space + str(self.get_label()) + "\n"
