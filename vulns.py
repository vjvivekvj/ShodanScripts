#FLOW OF CODE: 
# 1.QUERY SHODAN FOR A LABEL/KEYWORD
# 2.SAVE HOSTS IN HOSTS.TXT WHICH WERE FOUND TO HAVE THE SEARCHED KEYWORD
# 3.FOR EACH HOST IN HOSTS.TXT WE USE SHODAN TO TELL US THE VULNERABILITIES THAT THE DEVICE MAY HAVE BASED ON THE SERVICES IT IS RUNNING,
#	HOWEVER THE VULNERABILITIES MAY ALSO DEPEND ON THE CURRENT VERSION OF THE SERVICE THAT IS RUNNING ON THE DEVICE
#	WE WILL WORK ON VERSION SPECIFIC VULNERABILITIES AND THEIR EXPLOITS IN THE COMING DAYS
# 4.vuln.txt contains the vulnerabilities found

import subprocess

# add or change labels below to search in shodan
queries = ["ipcam"]
# save IPs that have above keyword on hosts.txt file
with open("hosts.txt", "w") as f:
	for query in queries:
		print("searching for label", query)
		args = 'shodan search --fields ip_str ' + query
		p1 = subprocess.run(args,shell = True,  stdout=f, text=True, input=query)
#file handling
hf = open("hosts.txt", "r")
v = open("vuln.txt", "w")
v.write("FILE CONTAINING VULNERABILITIES WHEN ENUMERATED ON QUERIED HOSTS\n")
v.close()

#read hosts.txt
data = hf.readlines()
for line in data:
	host = line.rsplit()
	print(host)
	#for each host search vulnerability using shodan host <ip_address> command
	if len(host)>0:
		args = "shodan host " + host[0]
		t = open("temp.txt", "w")
		p = subprocess.run(args, shell=True, stdout = t, text=True)
		t.close()
		t = open("temp.txt", "r")
		banner = t.readlines()
		for l in banner:
			if l.startswith("Vulnerabilities"):
				v = open("vuln.txt", "a")
				s = host[0] +" has " + l
				v.write(s)

