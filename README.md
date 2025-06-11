### Splunk

This project is used to store various useful search queries, scripts, and other resources for Splunk security monitoring.

# dnstwist-openai.sh
Searches for potential fake sites. It uses dnstwist tool to generate list of potential fake domains, filter unused sites,  and then uses opanai API to compare site content with original website. The result is save in JSON format in which could be easely forwarded to splunk index. 
