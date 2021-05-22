import argparse
import subprocess


def scan_hosts(query):
	# save IPs that have above keyword on hosts.txt file
	with open("hosts.txt", "w") as f:
		print("searching for ip address on shodan|", query)
		args = 'shodan search --fields ip_str ' + query
		p1 = subprocess.run(args,shell = True,  stdout=f, text=True, input=query)

def find_vuln():
	hf = open("hosts.txt", "r")
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


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("keyword", help="keyword to query in shodan")
	parser.add_argument("-l", "--limit", help="limit the number of results")
	args = parser.parse_args()
	if args.limit:
		query ='--limit ' + args.limit + " "
	query = query + args.keyword

	#create hosts.txt
	scan_hosts(query)

	#create vuln.txt
	v = open("vuln.txt", "w")
	v.write("contains vulnerability of hosts")
	v.close()

	#scan hosts.txt and output vulnerabilities to vuln.txt
	find_vuln()
