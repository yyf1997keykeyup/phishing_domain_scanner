import datetime
import errno
import os
import signal
from functools import wraps
from subprocess import *
from urllib.parse import urlparse

import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta


class TimeoutError(Exception):
    pass


def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator


def is_url_long(url):
    length = 1
    if len(url) >= 60:
        length = -1
    elif 44 <= len(url) <= 59:
        length = 0

    return length


def has_at(url):
    flag = 1
    index = url.find("@")
    if index != -1:
        flag = -1

    return flag


def has_dash(url):
    if url.find("-") != -1:
        return -1
    return 1


def has_multi_dots(url):
    count = url.count(".")
    if url.find("www.") != -1:
        count -= 1

    if count == 3:
        return 0
    elif count >= 4:
        return -1
    return 1


def has_valid_auth(url):
    url = 'https://' + url
    # todo: move it to yaml file
    valid_auth = {
        "Comodo", "Doster", "DigiCert", "Entrust Datacard", "Facebook", "Google", "GeoTrust", "GoDaddy", "LinkedIn",
        "Network Solutions", "RapidSSLonline", "SSL.com", "Sectigo", "Symantec", "Thawte", "VeriSign"
    }
    cmd = "curl -vvI " + url
    try:
        output = Popen(cmd, shell=True, stderr=PIPE, env={}).stderr.read().decode('UTF-8')
    except:
        return -1

    output = output[output.find("O=") + 2:]
    i_split = output.find(" ")
    if i_split != -1:
        output = output[:i_split]

    i_split = output.find(",")
    if i_split != -1:
        output = output[:i_split]

    if output in valid_auth:
        return 1
    return -1


def has_https(url):
    # e.g.: httpswww.chase.com.arabicnikah.com
    return 1 if url.find("https") == -1 else -1


def has_long_domain_register_period(url):
    url = tldextract.extract(url).domain + "." + tldextract.extract(url).suffix
    try:
        whois_result = whois.whois(url)
        creation_date = whois_result["creation_date"][0]
        expiration_date = whois_result["expiration_date"][0]
    except:
        return -1

    return 1 if expiration_date > creation_date + relativedelta(months=+12) else -1


def has_long_domain_period(url):
    url = tldextract.extract(url).domain + "." + tldextract.extract(url).suffix
    try:
        whois_result = whois.whois(url)
        creation_date = whois_result["creation_date"][0]
    except:
        return -1

    return 1 if datetime.datetime.now() > creation_date + relativedelta(months=+6) else -1


@timeout(10)
def has_many_tags(url):
    url = 'https://' + url
    try:
        program_html = requests.get(url).text
    except:
        return 0

    extracted_domain = tldextract.extract(url).domain
    soup = BeautifulSoup(program_html, 'lxml')

    meta_count = 0
    percentage_meta = 0
    meta_tags = soup.find_all('meta')
    for meta_tag in meta_tags:
        meta_tag_href = meta_tag.get('href')
        if not meta_tag_href:
            continue
        if tldextract.extract(meta_tag_href).domain != extracted_domain:
            meta_count += 1

    if len(meta_tags) != 0:
        percentage_meta = (meta_count * 100) // len(meta_tags)

    script_count = 0
    percentage_script = 0
    script_tags = soup.find_all('script')
    for script_tag in script_tags:
        script_tag_href = script_tag.get('href')
        if not script_tag_href:
            continue
        if tldextract.extract(script_tag_href).domain != extracted_domain:
            script_count += 1

    if len(script_tags) != 0:
        percentage_script = (script_count * 100) // len(script_tags)

    link_count = 0
    percentage_link = 0
    link_tags = soup.find_all('link')
    for link_tag in link_tags:
        link_tag_href = link_tag.get('href')
        if not link_tag_href:
            continue
        if tldextract.extract(link_tag_href).domain != extracted_domain:
            link_count += 1

    if len(link_tags) != 0:
        percentage_link = (link_count * 100) // len(link_tags)

    percentage_total = percentage_meta + percentage_script + percentage_link
    if percentage_total < 25:
        return 1
    elif percentage_total <= 60:
        return 0
    return -1


def is_url_valid(url):
    try:
        result = urlparse(url)
        return result.scheme and result.netloc
    except:
        return False


@timeout(10)
def redirect(url):
    url = 'https://' + url
    try:
        sh_result = Popen(["sh", "redirect.sh", url], stdout=PIPE).communicate()[0].decode('utf-8').split("\n")
    except:
        return 1, url

    sh_result_list = []
    for item in sh_result:
        sh_result_list.extend(item.replace("\r", " ").split(" "))

    redirect_count = 0
    for res_item in sh_result_list:
        if res_item.isdigit():
            conv = int(res_item)
            # HTTP redirect code is in[300, 310]
            if 300 < conv < 310:
                redirect_count += 1

    sh_result_list.reverse()
    for res_item in sh_result_list:
        if is_url_valid(res_item):
            url = res_item
            break

    if redirect_count <= 1:
        return 1, url
    elif redirect_count < 4:
        return 0, url
    return -1, url


def is_good_at_alexa_traffic(url):
    url = tldextract.extract(url).domain + "." + tldextract.extract(url).suffix
    html_content = requests.get("https://www.alexa.com/siteinfo/" + url).text
    soup = BeautifulSoup(html_content, "lxml")
    value = str(soup.find('div', {'class': "rankmini-rank"}))[42:].split("\n")[0].replace(",", "")

    if not value.isdigit():
        return -1
    return 1 if int(value) < 200000 else 0


def is_in_dns_record(url):
    try:
        whois.whois(tldextract.extract(url).domain + "." + tldextract.extract(url).suffix)
    except:
        return -1
    return 1


def get_positive_encoding(data):
    mapping = {-1: 2, 0: 0, 1: 1}
    return [mapping[data[i]] for i in range(len(data))]
