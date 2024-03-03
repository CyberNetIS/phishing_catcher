#!/usr/bin/env python
# Copyright (c) 2017 @x0rz
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
import re
import math

import certstream
import tqdm
import yaml
import time
import os
from Levenshtein import distance
from termcolor import colored, cprint
from tld import get_tld
import collections
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests
from bs4 import BeautifulSoup

from confusables import unconfuse

certstream_url = 'wss://certstream.calidog.io'

log_suspicious = os.path.dirname(os.path.realpath(__file__))+'/suspicious_domains_'+time.strftime("%Y-%m-%d")+'.log'
log_alert = os.path.dirname(os.path.realpath(__file__))+'/malicious_domains_'+time.strftime("%Y-%m-%d")+'.log'

suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'

external_yaml = os.path.dirname(os.path.realpath(__file__))+'/external.yaml'

certificate_domain_match_yaml = os.path.dirname(os.path.realpath(__file__))+'/certificate_domain_match.yaml'

pbar = tqdm.tqdm(desc='certificate_update', unit='cert')
domain_match =''

'''
def entropy(string):
    """Calculates the Shannon entropy of a string"""
    prob = [ float(string.count(c)) / len(string) for c in dict.fromkeys(list(string)) ]
    entropy = - sum([ p * math.log(p) / math.log(2.0) for p in prob ])
    return entropy
'''
def entropy(string):
    """Calculates the Shannon entropy of a string."""
    char_counts = collections.Counter(string)  # Efficiently count characters
    prob = [count / len(string) for count in char_counts.values()]  # Get probabilities
    entropy = -sum(p * math.log2(p) for p in prob)  # Calculate entropy using log2
    return entropy

def score_domain(domain):
    """Score `domain`.

    The highest score, the most probable `domain` is a phishing site.

    Args:
        domain (str): the domain to check.

    Returns:
        int: the score of `domain`.
    """
    score = 0
    for t in suspicious['tlds']:
        if domain.endswith(t):
            score += 20

    # Remove initial '*.' for wildcard certificates bug
    if domain.startswith('*.'):
        domain = domain[2:]

    # Removing TLD to catch inner TLD in subdomain (ie. paypal.com.domain.com)
    try:
        res = get_tld(domain, as_object=True, fail_silently=True, fix_protocol=True)
        domain = '.'.join([res.subdomain, res.domain])
    except Exception:
        pass

    # Higer entropy is kind of suspicious
    score += int(round(entropy(domain)*10))

    # Remove lookalike characters using list from http://www.unicode.org/reports/tr39
    domain = unconfuse(domain)

    words_in_domain = re.split(r"\W+", domain)

    # ie. detect fake .com (ie. *.com-account-management.info)
    if words_in_domain[0] in ['com', 'net', 'org']:
        score += 10

    # Testing keywords
    for word in suspicious['keywords']:
        if word in domain:
            score += suspicious['keywords'][word]

    # Testing Levenshtein distance for strong keywords (>= 70 points) (ie. paypol)
    for key in [k for (k,s) in suspicious['keywords'].items() if s >= 70]:
        # Removing too generic keywords (ie. mail.domain.com)
        for word in [w for w in words_in_domain if w not in ['email', 'mail', 'cloud']]:
            if distance(str(word), str(key)) == 1:
                score += 70

    # Lots of '-' (ie. www.paypal-datacenter.com-acccount-alert.com)
    if 'xn--' not in domain and domain.count('-') >= 4:
        score += domain.count('-') * 3

    # Deeply nested subdomains (ie. www.paypal.com.security.accountupdate.gq)
    if domain.count('.') >= 3:
        score += domain.count('.') * 3

    return score

def callback(message, context):
    """Callback handler for certstream events."""
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        for domain in all_domains:
            pbar.update(1)
            score = score_domain(domain.lower())

            # If issued from a free CA = more suspicious
            if "Let's Encrypt" == message['data']['leaf_cert']['issuer']['O']:
                score += 10
                # Domains Match
                for word in domain_match['keywords']:
                    if word in domain:
                        print("This is the DOMAIN: " + word)
                        score+=1000
                        tqdm.tqdm.write(
                            "[!] ALERT: "
                            "{} (score={})".format(colored(domain,'red'), score)
                        )


            if score >= 1000:
                tqdm.tqdm.write(
                    "[!] Malicious: "
                    "{} (score={})".format(colored(domain, 'magenta', attrs=['underline', 'bold']), score))
                with open(log_alert, 'a') as f:
                    f.write("{}\n".format(domain))
            elif score >= 100:
                tqdm.tqdm.write(
                    "[!] Suspicious: "
                    "{} (score={})".format(colored(domain, 'red', attrs=['underline']), score))
            elif score >= 90:
                tqdm.tqdm.write(
                    "[!] Likely    : "
                    "{} (score={})".format(colored(domain, 'yellow', attrs=['underline']), score))
            elif score >= 80:
                tqdm.tqdm.write(
                    "[+] Potential : "
                    "{} (score={})".format(colored(domain, attrs=['underline']), score))

            if score >= 75:
                with open(log_suspicious, 'a') as f:
                    f.write("{}\n".format(domain))

# Sending an email notification
def send_email(domian,cert_details):
    # Replace with your actual email credentials
    sender_email = "CyberNetIS.Intelligence@gmail.com"
    password = "your_password"

    # Recipient's email address
    receiver_email = "recipient_email@example.com"

    # Email subject and body
    subject = "Notification about suspected domain"
    body = "The following domain has been found to be registered using a Let's Encrypt Certificate: " + domian + "\n \n \n" +"Certificate Details : "

    # Create a multi-part message
    msg = MIMEMultipart()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject

    # Attach the plain text body
    msg.attach(MIMEText(body, "plain"))

    # Create a secure SSL context
    context = smtplib.ssl.create_default_context()

    # Send the email using Gmail's SMTP server
    with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

    print("Email sent successfully!")

# Scraping a webpage
def scrape_web_page(url):
    """Scrapes the content of a web page given its URL.

    Args:
        url (str): The URL of the web page to scrape.

    Returns:
        str: The scraped content of the web page.

    Raises:
        Exception: If an error occurs during the scraping process.
    """

    try:
        # Get the HTML content of the web page
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for error status codes

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(response.content, 'html.parser')

        # Extract the text content from the HTML
        scraped_content = soup.get_text(separator='\n')  # Separate paragraphs with newlines

        return scraped_content

    except Exception as e:
        print(f"Error scraping web page: {e}")
        raise  # Re-raise the exception to allow for error handling


if __name__ == '__main__':
    with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

    with open(external_yaml, 'r') as f:
        external = yaml.safe_load(f)

    with open(certificate_domain_match_yaml, 'r') as f:
        domain_match = yaml.safe_load(f)

    if external['override_suspicious.yaml'] is True:
        suspicious = external
    else:
        if external['keywords'] is not None:
            suspicious['keywords'].update(external['keywords'])

        if external['tlds'] is not None:
            suspicious['tlds'].update(external['tlds'])

    
    # Example usage:
 #   url = "https://www.example.com"  # Replace with the URL you want to scrape
 #   scraped_content = scrape_web_page(url)

#  print(scraped_content)

    certstream.listen_for_events(callback, url=certstream_url)
