import yaml
import os

certificate_domain_match_yaml = os.path.dirname(os.path.realpath(__file__))+'/certificate_domain_match.yaml'
suspicious_yaml = os.path.dirname(os.path.realpath(__file__))+'/suspicious.yaml'

with open(certificate_domain_match_yaml, 'r') as f:
        domain_match = yaml.safe_load(f)

with open(suspicious_yaml, 'r') as f:
        suspicious = yaml.safe_load(f)

for work in domain_match['keywords']:
        print(work)