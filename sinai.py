import argparse
import re
import sys
import geoip2.database
from heapq import nsmallest
import collections
from prettytable import PrettyTable
import itertools
from collections import Counter

#Check if we are running this on windows platform
is_windows = sys.platform.startswith('win')

#Console Colors
if is_windows:
        G = Y = B = R = W = G = Y = B = R = W = '' #use no terminal colors on windows
else:
        G = '\033[92m' #green
        Y = '\033[93m' #yellow
        B = '\033[94m' #blue
        R = '\033[91m' #red
        W = '\033[0m'  #white

def handle_error():
        print "Ooops.!! Something went error , please try again"

def banner():
        print """%s
                    ___ ___ _  _   _   ___
                   / __|_ _| \| | /_\ |_ _|
                   \__ \| || .` |/ _ \ | |
                   |___/___|_|\_/_/ \_\___|v1.0
                  %s%s
        # Apache HTTP Access Log Analyzer
        # Coded By ToRk @mohtork
        # Version 1.0%s
        """%(R,W,Y,W)

def parser_error(errmsg):
        print "Usage: python "+sys.argv[0]+" [Options] use -h for help"
        print R+"Error: "+errmsg+W
        sys.exit()


def msg(name=None):
    return '''  python sinai.py logfile --option
                example: python sinai.py example.log --topiploc
           '''

def parse_args():
        parser = argparse.ArgumentParser(prog='Sinai', description='Apache HTTP Access Log Analyzer', usage=msg())
        parser.error = parser_error
        parser._optionals.title = "OPTIONS"
        parser.add_argument('file', help = "Read the apache access log file")
        parser.add_argument('--getall', action='store_true', help = "Print All Data")
        parser.add_argument('--topip', action='store_true', help = "Print Top 10 IPs")
        parser.add_argument('--topiploc', action='store_true', help = "Print Top 10 IPs Location")
        parser.add_argument('--bandwidth', action='store_true', help = "Calculate Total Bandwidth")
        parser.add_argument('--topstatus', action='store_true', help = "Print status codes and their occurrence")
        parser.add_argument('--toprequest', action='store_true', help = "Print op Requests")
        parser.add_argument('--topref', action='store_true', help = "Print top Referrer")
        parser.add_argument('--topagent', action='store_true', help = "Print op Agents")
        parser.add_argument('--topip400', action='store_true', help = "Print top IPs that return 400 Code")
        parser.add_argument('--topip401', action='store_true', help = "Print top IPs that return 401 Code")
        parser.add_argument('--topip403', action='store_true', help = "Print top IPs that return 403 Code")
        parser.add_argument('--topip404', action='store_true', help = "Print top IPs that return 404 Code")
        parser.add_argument('--topip500', action='store_true', help = "Print top IPs that return 500 Code")
        parser.add_argument('--topip502', action='store_true', help = "Print top IPs that return 502 Code")
        parser.add_argument('--topip503', action='store_true', help = "Print top IPs that return 503 Code")
        parser.add_argument('--topip504', action='store_true', help = "Print top IPs that return 504 Code")
        parser.add_argument('--topref400', action='store_true', help = "Print top Referers that return 400 Code")
        parser.add_argument('--topref401', action='store_true', help = "Print top Referers that return 401 Code")
        parser.add_argument('--topref403', action='store_true', help = "Print top Referers that return 403 Code")
        parser.add_argument('--topref404', action='store_true', help = "Print top Referers that return 404 Code")
        parser.add_argument('--topref500', action='store_true', help = "Print top Referers that return 500 Code")
        parser.add_argument('--topref502', action='store_true', help = "Print top Referers that return 502 Code")
        parser.add_argument('--topref503', action='store_true', help = "Print top Referers that return 503 Code")
        parser.add_argument('--topref504', action='store_true', help = "Print top Referers that return 504 Code")
        parser.add_argument('--topreq400', action='store_true', help = "Print top Requests that return 400 Code")
        parser.add_argument('--topreq401', action='store_true', help = "Print top Requests that return 401 Code")
        parser.add_argument('--topreq403', action='store_true', help = "Print top Requests that return 403 Code")
        parser.add_argument('--topreq404', action='store_true', help = "Print top Requests that return 404 Code")
        parser.add_argument('--topreq500', action='store_true', help = "Print top Requests that return 500 Code")
        parser.add_argument('--topreq502', action='store_true', help = "Print top Requests that return 502 Code")
        parser.add_argument('--topreq503', action='store_true', help = "Print top Requests that return 503 Code")
        parser.add_argument('--topreq504', action='store_true', help = "Print top Requests that return 504 Code")
        return parser.parse_args()

class Apache(object):
	
	def ReadApache(self):
        	args  = parse_args()
        	file  = args.file
        	with open(file) as f:
                	mystr = '\t'.join([l.strip() for l in f])
        	return mystr

	def RegEx(self):
        	args = parse_args()
        	read = ap.ReadApache()
        	ip = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        	date = re.compile('\[\s*(\d+/\D+/.*?)\]') 
        	request = re.compile('"([^"]*) HTTP/1.\d"')
        	response = re.compile('HTTP\/1\.1\" ([0-9]{3})')
        	size = re.compile('\d+ (\d+)')
        	referrer = re.compile('"([^"]*)" \"')
        	agent = re.compile('" "([^"]*)"')
        	get_ip = re.findall(ip,read)
        	get_date = re.findall(date,read)
        	get_request = re.findall(request,read)
        	get_status = re.findall(response,read)
        	get_size = re.findall(size,read)
        	get_referrer = re.findall(referrer,read)
        	get_agent = re.findall(agent,read)
        	return (get_ip, get_date, get_request, get_status, get_size, get_referrer, get_agent)

ap = Apache()
get_obj = ap.RegEx()

def GetAll():
        args = parse_args()
        x = PrettyTable(["IP", "Date", "Request", "Status", "Size", "Referrer", "Agent"])
        x.align["IP"] = "l"
        x.padding_width = 1
        for ipv4, dates, requ, stat, size , refer, agen  in itertools.imap(None, get_obj[0], get_obj[1], get_obj[2], get_obj[3], get_obj[4], get_obj[5], get_obj[6]):
                x.add_row([ipv4, dates, requ[:20], stat, size, refer[:20], agen[:20]])
        return x.get_string()

def TopOccurr(num, request, total):
        args = parse_args()
        d = {}
        for i in get_obj[num]:
                if i in d:
                        d[i] = d[i]+1
                else:
                        d[i] = 1
        x = PrettyTable([request, total])
        x.align["Requests"] = "l"
        x.padding_width = 1
        for ref, occurnum in nsmallest(10, d.iteritems(), key=lambda (k,v): (-v,k)):
                x.add_row([ref[:120], occurnum])
        return x.get_string(start=0, end=10, sortby=total, reversesort=True)

def TopIpLocation():
        args = parse_args()
        geo = get_obj[0]
        c = collections.Counter(geo)
        common = dict(c.most_common(20))
        reader = geoip2.database.Reader("GeoLite2-City.mmdb") # Download "GeoLite2-city.mmdb" from
        x = PrettyTable(["IP", "Country", "Total Connections"])
        x.align["IP"] = "l"
        x.padding_width = 1
        for ips, values in common.iteritems():
                try:
                        locate_ip = reader.city(ips)
                        country = locate_ip.country.name
                        x.add_row([ips, country, values])
                except Exception as e:
                        print e
        return x.get_string(start=0,end=10,sortby="Total Connections", reversesort=True)

def TotalBandwidth():
        args = parse_args()
        band_in_bytes = sum(int(x) for x in get_obj[4])
        band_in_gigs  = band_in_bytes/(1024*1024*1204)
        x = PrettyTable(["Total Bandwidth in GB"])
        x.add_row([band_in_gigs])
        return x.get_string()


def StatusXx(i,c,A,B,status_code):
        List1 = []
        List2 = []
        args = parse_args()
        occurence ={}
        x = PrettyTable([i, c])
        x.align["IP"] = "l"
        x.padding_width = 1
        for j, k in itertools.imap(None, A, B):
                if k == status_code:
                        stat = k
                        List1.append(j)
                        List2.append(k)
        for item in List1:
                if item in occurence:
                        occurence[item] = occurence.get(item)+1
                else:
                        occurence[item] = 1
        for m, count in nsmallest(10, occurence.iteritems(), key=lambda (k,v): (-v,k)):
                x.add_row([m[:150], count])
        return x.get_string()

def Main():
        args = parse_args()
	
	if args.getall:
		print GetAll()
	
        elif args.topip:
                print TopOccurr(0, 'IP', 'Total Connection')

	elif args.topiploc:
                print TopIpLocation()

	elif args.bandwidth:
                print TotalBandwidth()
	
	elif args.topstatus:
                print TopOccurr(3, 'Status Code', 'Total Occurrence')

	elif args.toprequest:
                print TopOccurr(2, 'Requests', 'Total Occurrence')

	elif args.topref:
                print TopOccurr(5, 'Referrer', 'Total Occurrence')

	elif args.topagent:
                print TopOccurr(6, 'Agent', 'Total Occurrence')

	elif args.topip400:
                print StatusXx('IP Address', '400 Count', get_obj[0], get_obj[3], '400')

        elif args.topip401:
                print StatusXx('IP Address', '401 Count', get_obj[0], get_obj[3], '401')

        elif args.topip403:
                print StatusXx('IP Address', '403 Count', get_obj[0], get_obj[3], '403')

        elif args.topip404:
                print StatusXx('IP Address', '404 Count', get_obj[0], get_obj[3], '404')

        elif args.topip500:
                print StatusXx('IP Address', '500 Count', get_obj[0], get_obj[3], '500')

        elif args.topip502:
                print StatusXx('IP Address', '502 Count', get_obj[0], get_obj[3], '502')

        elif args.topip503:
                print StatusXx('IP Address', '503 Count', get_obj[0], get_obj[3], '503')

        elif args.topip504:
                print StatusXx('IP Address', '504 Count', get_obj[0], get_obj[3], '504')

        elif args.topref400:
                print StatusXx('Referrer', '400 Count', get_obj[5], get_obj[3], '400')

        elif args.topref401:
                print StatusXx('Referrer', '401 Count', get_obj[5], get_obj[3], '401')

        elif args.topref403:
                print StatusXx('Referrer', '403 Count', get_obj[5], get_obj[3], '403')

        elif args.topref404:
                print StatusXx('Referrer', '404 Count', get_obj[5], get_obj[3], '404')

        elif args.topref500:
                print StatusXx('Referrer', '500 Count', get_obj[5], get_obj[3], '500')

        elif args.topref502:
                print StatusXx('Referrer', '502 Count', get_obj[5], get_obj[3], '502')

        elif args.topref503:
                print StatusXx('Referrer', '503 Count', get_obj[5], get_obj[3], '503')

        elif args.topref504:
                print StatusXx('Referrer', '504 Count', get_obj[5], get_obj[3], '504')

        elif args.topreq400:
                print StatusXx('IP Address', '400 Count', get_obj[2], get_obj[3], '400')

        elif args.topreq401:
                print StatusXx('IP Address', '401 Count', get_obj[2], get_obj[3], '401')

        elif args.topreq403:
                print StatusXx('IP Address', '403 Count', get_obj[2], get_obj[3], '403')

        elif args.topreq404:
                print StatusXx('Request', '404 Count', get_obj[2], get_obj[3], '404')

        elif args.topreq500:
                print StatusXx('Request', '500 Count', get_obj[2], get_obj[3], '500')

        elif args.topreq502:
                print StatusXx('Request', '502 Count', get_obj[2], get_obj[3], '502')

        elif args.topreq503:
                print StatusXx('Request', '503 Count', get_obj[2], get_obj[3], '503')

        elif args.topreq504:
                print StatusXx('Request', '504 Count', get_obj[2], get_obj[3], '504')

	elif args.lasthour:
		print LastHour()

if __name__=="__main__":
        try:
                banner()
                Main()

        except KeyboardInterrupt:
                print "KeyboardInterrupt detected!\nByeBye!!..."
                sys.exit()

