import os
import time

import certstream
import tqdm
import yaml
from Levenshtein import distance

root = os.path.dirname(os.path.realpath(__file__))

log_output = root + '/phishing_domains_' + time.strftime("%Y-%m-%d") + '.log'

keyword_yaml = root + '/keyword.yaml'
keyword = None
keywords_list = None

pbar = tqdm.tqdm(desc='Phishing Domain Scanner Working', unit=' cert')


def merge(dict1, dict2):
    res = {**dict1, **dict2}
    return res


def get_phishing_score(domain):
    pbar.update(1)
    score = 0

    if domain.startswith('*.'):
        domain = domain[2:]
    if domain.endswith('.com.cn'):
        domain = domain[:-3]

    sub_domains = domain.split('.')

    if len(sub_domains) < 2:
        return score

    top_level_domain = sub_domains[-1]
    second_level_domain = sub_domains[-2]

    # Avoid good domains (e.g. google.com)
    if second_level_domain in keyword['whitelist']:
        return score

    sub_domains = sub_domains[:-1]
    # add score when meet blacklist
    for sub_domain in sub_domains:
        # too many false positive
        if sub_domain in ['email', 'mail', 'cloud']:
            continue
        for black_key in keywords_list:
            if black_key in sub_domain:
                score += keywords_list[black_key]

    # contain tlds in the middle 
    for sub_domain in sub_domains:
        if sub_domain != 'com' and sub_domain in keyword['tlds']:
            score += 15

    # contain some typo or tricks
    for sub_domain in sub_domains:
        if sub_domain in keyword['tricks']:
            score += 20

    # TODO: score by top_level_domain in the keyword.yaml
    if top_level_domain in keyword['tlds']:
        score += 5

    # Too many '-'
    if domain.count('-') >= 3:
        score += domain.count('-') * 5

    # Too many '.'
    if domain.count('.') >= 3:
        score += domain.count('.') * 4

    # Levenshtein distance (ie. paypol)
    for key, key_score in keywords_list.items():
        for domain_word in sub_domains:
            # too many false positive
            if domain_word in ['email', 'mail', 'cloud']:
                continue
            if distance(domain_word, key) == 1:
                score += key_score

    return score


def listen_func(message, _):
    if message['message_type'] != "certificate_update":
        return

    all_domains = message['data']['leaf_cert']['all_domains']
    for domain in all_domains:
        phishing_score = get_phishing_score(domain.lower())
        if phishing_score >= 75:
            print('suspicious: ' + domain + '  ' + str(phishing_score))
            with open(log_output, 'a') as f:
                f.write("{}\n".format(domain))
        # elif phishing_score != 0:
        #     print('pass: ' + domain + '  ' + str(phishing_score))


if __name__ == '__main__':
    with open(keyword_yaml, 'r') as f:
        keyword = yaml.safe_load(f)
        keywords_list = merge(keyword['whitelist'], keyword['blacklist'])
    certstream.listen_for_events(listen_func, url='wss://certstream.calidog.io')
