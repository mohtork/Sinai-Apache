# Sinai-Apache
Python cli tool to analyse Apache access log for quick troubleshooting
At this time you can use this tool to get information such as:

- The Top 10 IPs that make the higest connection to your web server
- The Top 10 IPs with their Locations
- Calculate the Total Bandwidth 
- The Top status codes and their occurrence
- The Top 10 Requests and their occurrence
- The Top Referrers and their occurrence
- The Top Agents and their occurrence
- The Top IPs that return status codes such as (400,401,403,404 and 500,502,503,504)
- The Top Referrers that return status codes such as (400,401,403,404 and 500,502,503,504)
- The Top Requests that return status codes such as (400,401,403,404 and 500,502,503,504)

# Usage
This Tool is easy to use 
python sinai.py access.log  --topip

to get help just type
python sinai.py --help 

the above command will print the 30 options you can use to analyse the Apache http Access Log

# In the Next version
I want to add a lot to the next version so any contribution would be great, for now I'm working on

- Get Requests , Referrers , IPs for the last hour

# Limits
- The tool took some time with the large files but it returns the result with now issue (I have tested it on a 6GB access log file)
- With large files you need More memory 
