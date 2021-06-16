import argparse
import subprocess
import operator
import matplotlib.pyplot as plt
import re

def scan_hosts(query):
	# save IPs that have above keyword on hosts.txt file
	with open("hosts.txt", "w") as f:
		print("searching for ip address on shodan|", query)
		args = 'shodan search --fields ip_str ' + query
		p1 = subprocess.run(args,shell = True,  stdout=f, text=True, input=query)

ports = {} 

def port_to_dict(port):
	global ports
	if not port[0] in ports:
		ports[port[0]] = 1
	else:
		ports[port[0]] += 1

def plot_ports(ports):
	#sort dictionary based on value
	ports = dict(sorted(ports.items(),key=operator.itemgetter(1),reverse=True))

	items_to_plot = min(len(ports), 10)	#plot only 10 values if there are more than 10 values
	open_ports = list(ports.keys())[:items_to_plot]		
	frequency = list(ports.values())[:items_to_plot]		
	fig = plt.figure(figsize = (10, 5))
 
	# creating the bar plot
	plt.bar(open_ports, frequency, color ='red',width = 0.4) 
	plt.xlabel("Open Ports")
	plt.ylabel("Frequency")
	plt.title("Common Open Ports")
	plt.show()		
	
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
			flag = 0
			for l in banner:
				if flag and re.match("^[0-9]", l.lstrip()):
					port = l.lstrip().split("/")[:1]
					port_to_dict(port)
				if l.startswith("Ports"):
					flag = 1

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
	#print(ports)
	plot_ports(ports)
