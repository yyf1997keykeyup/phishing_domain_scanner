# Phishing Domain Scanner

## Basic Workflow

1. Utilize CertStream to get real-time feed of CT logs.
2. Avoid normal domains by using whitelist. (*TODO!*: add more domain name to the whitelist)
3. Use score to quantify the suspiciousness of a domain name, add the score if:
    1. The tld is not common (e.g. .gp) *TODO!*
    2. Some common tlds is hidden in the domain (e.g. appleid-com.gp) *TODO!*
    3. Some words are similar to some common domains to fool users (e.g. amasonaws.com) *TODO!*
    4. TO ADD MORE ...
4. If the score exceeds to some specific threshold, then print it to the logs.