#Shodan Scripts to automate Shodan queries

#To install shodan api

easy_install shodan

#Or if you're running an older version of the Shodan Python library and want to upgrade:

easy_install -U shodan

#Once the tool is installed you have to initialize the environment with your API key using shodan init

shodan init YOUR_API_KEY

#Usage- keyword is what you want to search, optional argument -l to limit the no. of results
vuln_scan_2.py keyword -l 100
