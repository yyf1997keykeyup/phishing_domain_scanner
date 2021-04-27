import certstream
import os
import time
import yaml
from Levenshtein import distance

root = os.path.dirname(os.path.realpath(__file__))

log_output = root + '/phishing_domains_' + time.strftime("%Y-%m-%d") + '.log'

keyword_yaml = root + '/keyword.yaml'
keyword = None


def get_phishing_score(domain):
    score = 0

    if domain.startswith('*.'):
        domain = domain[2:]

    sub_domains = domain.split('.')

    if len(sub_domains) < 2:
        return score

    top_level_domain = sub_domains[-1]
    second_level_domain = sub_domains[-2]

    # TODO: avoid good domains (e.g. google.com)
    if top_level_domain == 'com' and second_level_domain in keyword['whitelist']:
        return score

    for sub_domain in sub_domains:
        if sub_domain in keyword['blacklist']:
            score += 75

    # TODO: score by top_level_domain in the keyword.yaml
    if top_level_domain in keyword['tlds']:
        score += 10

    # Lots of '-'
    if domain.count('-') >= 4:
        score += domain.count('-') * 5

    # Lots of '.'
    if domain.count('.') >= 4:
        score += domain.count('.') * 3

    # Levenshtein distance (ie. paypol)
    keywords_list = keyword['generic'] = keyword['whitelist']
    for key, key_score in keywords_list.items():
        for domain_word in sub_domains:
            if distance(str(domain_word), str(key)) == 1:
                score += key_score * 2

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
    certstream.listen_for_events(listen_func, url='wss://certstream.calidog.io')
