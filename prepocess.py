import csv

import pandas as pd

from utils import *


def format_phishing_domain_log(input_path, output_path):
    f_output = open(output_path, "w")
    ret_domain_set = set()
    with open(input_path, 'r') as f:
        lines = f.readlines()
        for line in lines:
            ret_domain_set.add(format_phishing_domain(line))
    for ret_domain in ret_domain_set:
        f_output.writelines(ret_domain + '\n')
    f_output.close()


def format_phishing_domain(domain):
    i = domain.find('https://')
    j = domain.find('http://')
    if i != -1:
        domain = domain[8:]
    elif j != -1:
        domain = domain[7:]

    k = domain.find('/')
    if k != -1:
        domain = domain[:k - len(domain)]
    return domain


def format_moz_500_domain_list(input_path, output_path):
    f_output = open(output_path, "w")
    ret_domain_set = set()
    with open(input_path, newline='') as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            ret_domain_set.add(row['Root Domain'])
    for ret_domain in ret_domain_set:
        f_output.writelines(ret_domain + '\n')
    f_output.close()


# format_moz_500_domain_list('/Users/yanyufeng/Downloads/top500Domains.csv', 'logs/false_phishing_domain.log')


def extract_features(url, is_ph):
    redirect_status, _ = redirect(url)
    features_extracted = [
        is_url_long(url),
        has_at(url),
        has_dash(url),
        has_multi_dots(url),
        has_valid_auth(url),
        has_https(url),
        has_long_domain_register_period(url),
        has_long_domain_period(url),
        has_many_tags(url),
        redirect_status,
        is_good_at_alexa_traffic(url),
        is_in_dns_record(url),
        1 if is_ph else -1,
    ]
    return get_positive_encoding(features_extracted)


def get_features():
    columns = ['long_url_len', 'has_at', 'has_dash', 'has_multi_dots', 'has_valid_auth', 'has_https',
               'has_long_domain_register_period', 'has_long_domain_period', 'has_many_tags', 'redirect_status',
               'is_good_at_alexa_traffic', 'is_in_dns_record', 'label']
    with open('logs/false_phishing_domain.log', 'r') as f:
        features_list = []
        lines = f.readlines()
        for i in range(len(lines)):
            print('count: ', i)
            line = lines[i]
            features = extract_features(line[:-1], False)
            features_list.append(features)
        dataframe = pd.DataFrame.from_records(features_list, columns=columns)
        dataframe.to_csv('output_false.csv')

    with open('logs/true_phishing_domain.log', 'r') as f:
        features_list = []
        lines = f.readlines()
        for i in range(len(lines)):
            print('count: ', i)
            line = lines[i]
            features = extract_features(line[:-1], True)
            features_list.append(features)
        dataframe = pd.DataFrame.from_records(features_list, columns=columns)
        dataframe.to_csv('output_true.csv')

    # todo: then combine output_true.csv and output_false.csv together -> output.csv

# get_features()
