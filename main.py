import certstream
import os
import time
import yaml

root = os.path.dirname(os.path.realpath(__file__))

log_output = root + '/phishing_domains_' + time.strftime("%Y-%m-%d") + '.log'

keyword_yaml = root + '/keyword.yaml'
keyword = None


def get_phishing_score(domain):
    score = 0
    sub_domains = domain.split('.')

    if len(sub_domains) < 2:
        return

    top_level_domain = sub_domains[-1]
    second_level_domain = sub_domains[-2]

    # TODO: avoid good domains (e.g. google.com)
    if second_level_domain in keyword_yaml['whitelist']:
        return

    # TODO: score by top_level_domain in the keyword.yaml
    if top_level_domain in keyword_yaml['tlds']:
        score += 10

    return score


def listen_func(message, _):
    if message['message_type'] != "certificate_update":
        return

    all_domains = message['data']['leaf_cert']['all_domains']
    for domain in all_domains:
        print(domain)
        phishing_score = get_phishing_score(domain.lower())

        if phishing_score >= 75:
            with open(log_output, 'a') as f:
                f.write("{}\n".format(domain))


if __name__ == '__main__':
    with open(keyword_yaml, 'r') as f:
        keyword = yaml.safe_load(f)
    certstream.listen_for_events(listen_func, url='wss://certstream.calidog.io')
