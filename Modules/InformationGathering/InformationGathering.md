# Table of Contents

## Information Gathering

This section just covers a high level overvied of information gathering and its uses. The module breaks information gathering into two stages, Passive and Active information gathering. Passive is done without touching company infrastructure by using public resources. Active uses scripts and tools to gain information on the target. It also mentions creating a HackerOne account to begin bug bounty hunting.

# Passive Information Gathering

## WHOIS

WHOIS is a tool that pulls all of the DNS records for registered domains and give information for the site being tested. You simply just run whois "domain.com". This returns information like the nameservers, the phone number associated with the site, the email addres, etc.

## DNS

This section covers what DNS is, and tools to leverage it such as Nslookup & DIG. The section characterizes DNS as the internets phone book. Essentially, every site has an IP address, and this is hard for people to remember, so DNS saves these IP addresses as names (e.g. Google.com).

Nslookup and DIG lets us get information for domanin name servers. You can get information such as the server associated with the mx records on a domain.  

## Passive Subdomain Enumeration

Subdomain enumeration is the action of mapping all available subdomains withing a domain name to increase the attack surface. This could uncover hidden management backend panels or intranet web applications that admins tried to keep safe by hiding it.

VirusTotal maintains its DNS replication service, which is developed by preserving DNS resolutions made when users visit URLs given by them.

We can also use certificates to extract subdomains. Certificate Transparency is a project that requires all certs issued by a certificate authority to be published in a publically accessible log.

We can examine these logs using `https://censys.com/` or `https://crt.sh/`.

We can also do this through command line by running this:
`export TARGET="facebook.com"
curl -s "https://crt.sh/?q=${TARGET}&output=json" | jq -r '.[] | "\(.name_value)\n\(.common_name)"' | sort -u > "${TARGET}_crt.sh.txt"
`

This will return the data in json formation. 

jq is a json processor, and this specific command splits this output to print the certs name and common name one per line. 

sort -u just sorts the output and removes duplicates.

TheHarvester is a tool that collects emails, names, subdomains, IP addresses, and URLs from public data sources.

We will only be using for now:
`Baidu 	Baidu search engine.
Bufferoverun 	Uses data from Rapid7's Project Sonar - www.rapid7.com/research/project-sonar/
Crtsh 	Comodo Certificate search.
Hackertarget 	Online vulnerability scanners and network intelligence to help organizations.
Otx 	AlienVault Open Threat Exchange - https://otx.alienvault.com
Rapiddns 	DNS query tool, which makes querying subdomains or sites using the same IP easy.
Sublist3r 	Fast subdomains enumeration tool for penetration testers
Threatcrowd 	Open source threat intelligence.
Threatminer 	Data mining for threat intelligence.
Trello 	Search Trello boards (Uses Google search)
Urlscan 	A sandbox for the web that is a URL and website scanner.
Vhost 	Bing virtual hosts search.
Virustotal 	Domain search.
Zoomeye 	A Chinese version of Shodan.
`
And we will put these in a text file called HarvesterSources.txt

Then we can run TheHarvester with:
`export TARGET="facebook.com"
cat CommonLists/HarvesterSources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
`

## Passive Infrastructure Identification

Netcraft is a tool that can give some infrastucture information passively. We can using this tool here `https://sitereport.netcraft.com`.

This tool can give us:
`Background 	General information about the domain, including the date it was first seen by Netcraft crawlers.
Network 	Information about the netblock owner, hosting company, nameservers, etc.
Hosting history 	Latest IPs used, webserver, and target OS.`

Specifically, the hosting history and the latest IP is useful because it can give us the actual IP address from the webserver before it was placed behind a load balancer. And if it configured incorrectly, we can connect directly.

We can also use the WayBackMachine to look at old versions of a website and potentially identify old vulnerabilities. If these vulns were not removed correctly, it is possible to leverage this information to gain a foothold on the site we are attacking.

# Active Information Gathering

## Active Infrastructure identification

Determining the web server type for the web app, is one of the steps when doing active infrastructure indentification. This can give us information on how to begin our attack. You can use the response headers to identify info about the backend server. Things like the cookie, can tell you about what language is running in the background.

`   .NET: ASPSESSIONID<RANDOM>=<COOKIE_VALUE>
    PHP: PHPSESSID=<COOKIE_VALUE>
    JAVA: JSESSION=<COOKIE_VALUE>
`

And determining if it is running Apache, IIS, etc can help determine the OS on the machine.

There are also tools to help with active identification.

One tool is Whatweb that recognizes web technologies, content management systems, blogging platforms, statistic/analytics packages, Javascript libraries, web servers, and embedded devices.

You can control the level of aggression on whatweb with the -a flag, and -v flag gives verbose output.

The tests in this section are:

What Apache version is running on app.inlanefreight.local? (Format: 0.0.0):
To solve this, connect to the VPN using sudo openvpn --config file.ovpn
then run `curl -I IP`
The answer was 2.4.41. 

Which CMS is used on app.inlanefreight.local? (Format: word):
You first need to add this line to your /etc/hosts file `10.129.70.45 app.inlanefreight.local dev.inlanefreight.local`

Then you can run `whatapp -a3 app.inlanefreight.local -v`

This returns that the CMS (Content Management System) is Joomla! and the answer is Joomla.

On which operating system is the dev.inlanefreight.local webserver running on? (Format: word):
The answer to this is running the same command as above but with dev.inlanefreight.local and you find the operating system to be Ubuntu Linux. The answer is only looking for Ubuntu though.

## Active Subdomain Enumeration

The zone transfer is how a secondary DNS recieves info from the primary. The master-slave approach is used to organize DNS servers withing a domain. The slave receives the updated DNS info from the master. The master should be configured to enable zone transfers from the secondary.

We can use `https://hackertarget.com/zone-transfer/` to get this information.

We can do `nslookup -type=NS [website]` to identify the nameserver.

Then run `nslookup -type=any -query=AXFR [website] [nameserver]` to get the same information

GoBuster is a tool we can use for subdomain enumeration. We can use a wordlist along with gobuster if we are looking for words in patterns instead of numbers. In the past we found a pattern that looked like `lert-api-shv-{NUMBER}-sin6.facebook.com`. We can use this pattern to find additional subdomains.

The tests for this section are:

Submit the FQDN of the nameserver for the "inlanefreight.htb" domain as the answer.
The answer here was to run `nslookup -type=NS inlanefreight.htb [IP]`. Then the result was ns.inlanefreight.htb

Identify how many zones exist on the target nameserver. Submit the number of found zones as the answer. 
The answer here was to run `dig ANY inlanefreight.htb @[IP]`, then the count the result.

Find and submit the contents of the TXT record as the answer.
This one was confusing, you had to dig for axfr records the two returned zones, then iterate over the a records for txt files. It was hard to follow and I am still confused.

What is the FQDN of the IP address 10.10.34.136? 
Once again running the dig command on the two given zones, you can find the FQDN associated with the IP address.

What FQDN is assigned to the IP address 10.10.1.5? Submit the FQDN as the answer. 
Same process

 Which IP address is assigned to the "us.inlanefreight.htb" subdomain. Submit the IP address as the answer. 
Same process as above but reversed

Submit the number of all "A" records from all zones as the answer. 
Run `dig @10.129.249.31 NS axfr inlanefreight.htb` and `dig @10.129.249.31 NS axfr internal.inlanefreight.htb` and count the records. The total was 27. 

## Virtual Hosts

A virtual host allows a single webserver to host multiple web pages. This can be done by IP-based Virtual Hosting or Name-based Virtual hosting.

IP-Based can have multiple network interfaces. Then multiple IP addresses, or interface aliaseses, can be configured on each network interface of a host. The servers or virtual servers running on the host can bind to one or more IP addresses. That makes it so different servers can be addressed under different IP addresses. From the clients POV, the servers are independent.

In name-based, the distinction for which domain was requested is made at the application level. For example, multiple names can correspond to the same IP (e.g example.inlanefreight.htb, and example2.inlanefreight.htb can both have the same IP). On the server, these are seperating using folders, so it might look like example1 corresponds to /var/www/admin on the server, and example2 corresponds to /var/www/backup.

Using FFUF we can automate VHost discover. FFUF is a fuzzing tool. Some useful parameters:
`MATCHER OPTIONS:
  -mc                 Match HTTP status codes, or "all" for everything. (default: 200,204,301,302,307,401,403,405)
  -ml                 Match amount of lines in response
  -mr                 Match regexp
  -ms                 Match HTTP response size
  -mw                 Match amount of words in response

FILTER OPTIONS:
  -fc                 Filter HTTP status codes from response. Comma separated list of codes and ranges
  -fl                 Filter by amount of lines in response. Comma separated list of line counts and ranges
  -fr                 Filter regexp
  -fs                 Filter HTTP response size. Comma separated list of sizes and ranges
  -fw                 Filter by amount of words in response. Comma separated list of word counts and ranges`

We can match or filter responses based on different options. The web server responds with a default and static website every time we issue an invalid virtual host in the HOST header. We can use the filter by size -fs option to discard the default response as it will always have the same size.

An example of running ffuf `ffuf -w ./vhosts -u http://192.168.10.10 -H "HOST: FUZZ.randomtarget.com" -fs 612`

Where -w is the wordlist to fuzz on, -u is the ip, -H is the host with FUZZ being the word relaced, and  -fs being a filter to remove pages that are size 612.

Tests on this section:
Enumerate the target and find a vHost that contains flag No. 1. Submit the flag value as your answer (in the format HTB{DATA}). 

Running this gets back a list of vhosts:
`ffuf -w ../SecLists/Discovery/DNS/namelist.txt -u http://10.129.41.55 -H "HOST: FUZZ.inlanefreight.htb" -fs 10918`

They are: customers, app, ap, citrix, dmz, and www.
Add these to /etc/hosts

Then the answer to the first test is to run:
`curl -s http://10.129.41.55 -H "Host: ap.inlanefreight.htb"`

The subsequent tests in order are solved by running:
`curl -s http://10.129.41.55 -H "Host: app.inlanefreight.htb"`
`curl -s http://10.129.41.55 -H "Host: citrix.inlanefreight.htb"`
`curl -s http://10.129.41.55 -H "Host: customers.inlanefreight.htb"`
`curl -s http://10.129.41.55 -H "Host: dmz.inlanefreight.htb"`

## Crawling

This page covers crawling of a website using Zap's spider functionality. We use the crawling process to find as many pages and subdirectories belonging to a website as possible. It also briefly covers the manual request editor and built in fuzzer. I have already worked heavily with this tool in the previous module.

It also covers how to use ffuf to perform a further crawl to see if spider missed anything.
This is the example code given `ffuf -recursion -recursion-depth 1 -u http://192.168.10.10/FUZZ -w /opt/useful/SecLists/Discovery/Web-Content/raft-small-directories-lowercase.txt`


# Putting it all Together

## Information Gathering - Web - Skills Assessment

This skill assessment has us perform a passsive and active information gathering against githubapp.com. We are expected to exclude 
`- atom-io.githubapp.com
- atom-io-staging.githubapp.com
- email.enterprise-staging.githubapp.com
- email.haystack.githubapp.com
- reply.githubapp.com`

The first question is what is the IANA ID number. Simply running whois githubapp.com gives the answer.

The next question is:
What is the last mail`server returned when querying the MX records for githubapp.com? 
Running `dig MX githubapp.com` gets the answer

Next question:
Perform active infrastructure identification against the host https://i.imgur.com. What server name is returned for the host? 

Running `./whatweb -a3 https://i.imgur.com` returns a lot of things including `HTTPServer[cat factory 1.0]`
The answer is cat factory 1.0

Next question:
Perform subdomain enumeration against the target githubapp.com. Which subdomain has the word 'triage' in the name?

Using cert.sh (pronounced search) you can find all registered certs and find the answer is:
`data-triage-reports.githubapp.com`

