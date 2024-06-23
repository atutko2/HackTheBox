This Module had an update. So I am redoing it.

# Intro

## Intro

Web Reconnaissance is the foundation of a thorough security assessment. This process involves systematically and meticulously collecting information about a target website or web application. Think of it as the preparatory phase before delving into deeper analysis and potential exploitation. It forms a critical part of the "Information Gathering" phase of the Penetration Testing Process.

The primary goals of web reconnaissance include:

    Identifying Assets: Uncovering all publicly accessible components of the target, such as web pages, subdomains, IP addresses, and technologies used. This step provides a comprehensive overview of the target's online presence.
    Discovering Hidden Information: Locating sensitive information that might be inadvertently exposed, including backup files, configuration files, or internal documentation. These findings can reveal valuable insights and potential entry points for attacks.
    Analysing the Attack Surface: Examining the target's attack surface to identify potential vulnerabilities and weaknesses. This involves assessing the technologies used, configurations, and possible entry points for exploitation.
    Gathering Intelligence: Collecting information that can be leveraged for further exploitation or social engineering attacks. This includes identifying key personnel, email addresses, or patterns of behaviour that could be exploited.


Attackers leverage this information to tailor their attacks, allowing them to target specific weaknesses and bypass security measures. Conversely, defenders use recon to proactively identify and patch vulnerabilities before malicious actors can leverage them.


```
Port Scanning -> Using Nmap to scan for open ports -> High risk of detection by IDS
Vuln Scanning -> Running Nessus against a web app -> High risk of detection
Network Mapping -> Using traceroute to determine the path packets take to reach the server, revealing potential network hops -> Medium to High
Banner Grabbing -> Connecting to a web server on port 90 and examing the http banner to identify the web server software and version (i.e. netcat/curl) -> Low
OS Fingerprinting -> Using Nmap's OS detection to determine Windows/Linux/Etc -> Low
Service Enum -> Using Nmaps -sV to determine if its Apache or Nginx -> Low
Web Spidering -> Running a web crawler like Burp Suite Spider -> Low to Meduim
```

Active reconnaissance provides a direct and often more comprehensive view of the target's infrastructure and security posture. However, it also carries a higher risk of detection, as the interactions with the target can trigger alerts or raise suspicion.

Passive is all very low risk of detection.

```
Search Engine Queries -> Searching Google for "[Target Name] employees" to find employee information or social media profiles.
WHOIS Lookups -> Performing a WHOIS lookup on a target domain to find the registrant's name, contact information, and name servers.
DNS -> Using dig to enumerate subdomains of a target domain.
Web Archive Analysis -> Using the Wayback Machine to view past versions of a target website to see how it has changed over time.
Social Media Analysis -> Searching LinkedIn for employees of a target organisation to learn about their roles, responsibilities, and potential social engineering targets.
Code Repositories -> Searching GitHub for code snippets or repositories related to the target that might contain sensitive information or code vulnerabilities.
```

Passive reconnaissance is generally considered stealthier and less likely to trigger alarms than active reconnaissance. However, it may yield less comprehensive information, as it relies on what's already publicly accessible.

In this module, we will delve into the essential tools and techniques used in web reconnaissance, starting with WHOIS. Understanding the WHOIS protocol provides a gateway to accessing vital information about domain registrations, ownership details, and the digital infrastructure of targets. This foundational knowledge sets the stage for more advanced recon methods we'll explore later.

# WHOIS

## WHOIS

WHOIS is a widely used query and response protocol designed to access databases that store information about registered internet resources. Primarily associated with domain names, WHOIS can also provide details about IP address blocks and autonomous systems. Think of it as a giant phonebook for the internet, letting you look up who owns or is responsible for various online assets.

```
    Domain Name: The domain name itself (e.g., example.com)
    Registrar: The company where the domain was registered (e.g., GoDaddy, Namecheap)
    Registrant Contact: The person or organization that registered the domain.
    Administrative Contact: The person responsible for managing the domain.
    Technical Contact: The person handling technical issues related to the domain.
    Creation and Expiration Dates: When the domain was registered and when it's set to expire.
    Name Servers: Servers that translate the domain name into an IP address.
```

The history of WHOIS is intrinsically linked to the vision and dedication of Elizabeth Feinler, a computer scientist who played a pivotal role in shaping the early internet.

In the 1970s, Feinler and her team at the Stanford Research Institute's Network Information Center (NIC) recognised the need for a system to track and manage the growing number of network resources on the ARPANET, the precursor to the modern internet. Their solution was the creation of the WHOIS directory, a rudimentary yet groundbreaking database that stored information about network users, hostnames, and domain names.

WHOIS data serves as a treasure trove of information for penetration testers during the reconnaissance phase of an assessment. It offers valuable insights into the target organisation's digital footprint and potential vulnerabilities:

    Identifying Key Personnel: WHOIS records often reveal the names, email addresses, and phone numbers of individuals responsible for managing the domain. This information can be leveraged for social engineering attacks or to identify potential targets for phishing campaigns.
    Discovering Network Infrastructure: Technical details like name servers and IP addresses provide clues about the target's network infrastructure. This can help penetration testers identify potential entry points or misconfigurations.
    Historical Data Analysis: Accessing historical WHOIS records through services like WhoisFreaks can reveal changes in ownership, contact information, or technical details over time. This can be useful for tracking the evolution of the target's digital presence.

## Using WHOIS

Let's consider three scenarios to help illustrate the value of WHOIS data.

An email security gateway flags a suspicious email sent to multiple employees within a company. The email claims to be from the company's bank and urges recipients to click on a link to update their account information. A security analyst investigates the email and begins by performing a WHOIS lookup on the domain linked in the email.

The WHOIS record reveals the following:

    Registration Date: The domain was registered just a few days ago.
    Registrant: The registrant's information is hidden behind a privacy service.
    Name Servers: The name servers are associated with a known bulletproof hosting provider often used for malicious activities.

This combination of factors raises significant red flags for the analyst. The recent registration date, hidden registrant information, and suspicious hosting strongly suggest a phishing campaign. The analyst promptly alerts the company's IT department to block the domain and warns employees about the scam.

Further investigation into the hosting provider and associated IP addresses may uncover additional phishing domains or infrastructure the threat actor uses.

A security researcher is analysing a new strain of malware that has infected several systems within a network. The malware communicates with a remote server to receive commands and exfiltrate stolen data. To gain insights into the threat actor's infrastructure, the researcher performs a WHOIS lookup on the domain associated with the command-and-control (C2) server.

The WHOIS record reveals:

    Registrant: The domain is registered to an individual using a free email service known for anonymity.
    Location: The registrant's address is in a country with a high prevalence of cybercrime.
    Registrar: The domain was registered through a registrar with a history of lax abuse policies.

Based on this information, the researcher concludes that the C2 server is likely hosted on a compromised or "bulletproof" server. The researcher then uses the WHOIS data to identify the hosting provider and notify them of the malicious activity.



A cybersecurity firm tracks the activities of a sophisticated threat actor group known for targeting financial institutions. Analysts gather WHOIS data on multiple domains associated with the group's past campaigns to compile a comprehensive threat intelligence report.

By analysing the WHOIS records, analysts uncover the following patterns:

    Registration Dates: The domains were registered in clusters, often shortly before major attacks.
    Registrants: The registrants use various aliases and fake identities.
    Name Servers: The domains often share the same name servers, suggesting a common infrastructure.
    Takedown History: Many domains have been taken down after attacks, indicating previous law enforcement or security interventions.

These insights allow analysts to create a detailed profile of the threat actor's tactics, techniques, and procedures (TTPs). The report includes indicators of compromise (IOCs) based on the WHOIS data, which other organisations can use to detect and block future attacks.

Before using the whois command, you'll need to ensure it's installed on your Linux system. It's a utility available through linux package managers, and if it's not installed, it can be installed simply with

The simplest way to access WHOIS data is through the whois command-line tool. Let's perform a WHOIS lookup on facebook.com:

The WHOIS output for facebook.com reveals several key details:

    Domain Registration:
        Registrar: RegistrarSafe, LLC
        Creation Date: 1997-03-29
        Expiry Date: 2033-03-30

    These details indicate that the domain is registered with RegistrarSafe, LLC, and has been active for a considerable period, suggesting its legitimacy and established online presence. The distant expiry date further reinforces its longevity.

    Domain Owner:
        Registrant/Admin/Tech Organization: Meta Platforms, Inc.
        Registrant/Admin/Tech Contact: Domain Admin

    This information identifies Meta Platforms, Inc. as the organization behind facebook.com, and "Domain Admin" as the point of contact for domain-related matters. This is consistent with the expectation that Facebook, a prominent social media platform, is owned by Meta Platforms, Inc.

    Domain Status:
        clientDeleteProhibited, clientTransferProhibited, clientUpdateProhibited, serverDeleteProhibited, serverTransferProhibited, and serverUpdateProhibited

    These statuses indicate that the domain is protected against unauthorized changes, transfers, or deletions on both the client and server sides. This highlights a strong emphasis on security and control over the domain.

    Name Servers:
        A.NS.FACEBOOK.COM, B.NS.FACEBOOK.COM, C.NS.FACEBOOK.COM, D.NS.FACEBOOK.COM

    These name servers are all within the facebook.com domain, suggesting that Meta Platforms, Inc. manages its DNS infrastructure. It is common practice for large organizations to maintain control and reliability over their DNS resolution.

Overall, the WHOIS output for facebook.com aligns with expectations for a well-established and secure domain owned by a large organization like Meta Platforms, Inc.

While the WHOIS record provides contact information for domain-related issues, it might not be directly helpful in identifying individual employees or specific vulnerabilities. This highlights the need to combine WHOIS data with other reconnaissance techniques to understand the target's digital footprint comprehensively.

# DNS & Subdomains

## DNS

This is all in the other file if I need an explanation of DNS.

## Digging DNS

Having established a solid understanding of DNS fundamentals and its various record types, let's now transition to the practical. This section will explore the tools and techniques for leveraging DNS for web reconnaissance.

DNS reconnaissance involves utilizing specialized tools designed to query DNS servers and extract valuable information. Here are some of the most popular and versatile tools in the arsenal of web recon professionals:

```
Tool 	Key Features 	Use Cases
dig 	Versatile DNS lookup tool that supports various query types (A, MX, NS, TXT, etc.) and detailed output. 	Manual DNS queries, zone transfers (if allowed), troubleshooting DNS issues, and in-depth analysis of DNS records.
nslookup 	Simpler DNS lookup tool, primarily for A, AAAA, and MX records. 	Basic DNS queries, quick checks of domain resolution and mail server records.
host 	Streamlined DNS lookup tool with concise output. 	Quick checks of A, AAAA, and MX records.
dnsenum 	Automated DNS enumeration tool, dictionary attacks, brute-forcing, zone transfers (if allowed). 	Discovering subdomains and gathering DNS information efficiently.
fierce 	DNS reconnaissance and subdomain enumeration tool with recursive search and wildcard detection. 	User-friendly interface for DNS reconnaissance, identifying subdomains and potential targets.
dnsrecon 	Combines multiple DNS reconnaissance techniques and supports various output formats. 	Comprehensive DNS enumeration, identifying subdomains, and gathering DNS records for further analysis.
theHarvester 	OSINT tool that gathers information from various sources, including DNS records (email addresses). 	Collecting email addresses, employee information, and other data associated with a domain from multiple sources.
Online DNS Lookup Services 	User-friendly interfaces for performing DNS lookups. 	Quick and easy DNS lookups, convenient when command-line tools are not available, checking for domain availability or basic informatio
```

The dig command (Domain Information Groper) is a versatile and powerful utility for querying DNS servers and retrieving various types of DNS records. Its flexibility and detailed and customizable output make it a go-to choice.

```
dig domain.com 	Performs a default A record lookup for the domain.
dig domain.com A 	Retrieves the IPv4 address (A record) associated with the domain.
dig domain.com AAAA 	Retrieves the IPv6 address (AAAA record) associated with the domain.
dig domain.com MX 	Finds the mail servers (MX records) responsible for the domain.
dig domain.com NS 	Identifies the authoritative name servers for the domain.
dig domain.com TXT 	Retrieves any TXT records associated with the domain.
dig domain.com CNAME 	Retrieves the canonical name (CNAME) record for the domain.
dig domain.com SOA 	Retrieves the start of authority (SOA) record for the domain.
dig @1.1.1.1 domain.com 	Specifies a specific name server to query; in this case 1.1.1.1
dig +trace domain.com 	Shows the full path of DNS resolution.
dig -x 192.168.1.1 	Performs a reverse lookup on the IP address 192.168.1.1 to find the associated host name. You may need to specify a name server.
dig +short domain.com 	Provides a short, concise answer to the query.
dig +noall +answer domain.com 	Displays only the answer section of the query output.
dig domain.com ANY 	Retrieves all available DNS records for the domain (Note: Many DNS servers ignore ANY queries to reduce load and prevent abuse, as per RFC 8482).
```

This output is the result of a DNS query using the dig command for the domain google.com. The command was executed on a system running DiG version 9.18.24-0ubuntu0.22.04.1-Ubuntu. The output can be broken down into four key sections:

    Header

        ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 16449: This line indicates the type of query (QUERY), the successful status (NOERROR), and a unique identifier (16449) for this specific query.
            ;; flags: qr rd ad; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0: This describes the flags in the DNS header:
                qr: Query Response flag - indicates this is a response.
                rd: Recursion Desired flag - means recursion was requested.
                ad: Authentic Data flag - means the resolver considers the data authentic.
                The remaining numbers indicate the number of entries in each section of the DNS response: 1 question, 1 answer, 0 authority records, and 0 additional records.

        ;; WARNING: recursion requested but not available: This indicates that recursion was requested, but the server does not support it.

    Question Section
        ;google.com. IN A: This line specifies the question: "What is the IPv4 address (A record) for google.com?"

    Answer Section
        google.com. 0 IN A 142.251.47.142: This is the answer to the query. It indicates that the IP address associated with google.com is 142.251.47.142. The '0' represents the TTL (time-to-live), indicating how long the result can be cached before being refreshed.

    Footer

        ;; Query time: 0 msec: This shows the time it took for the query to be processed and the response to be received (0 milliseconds).

        ;; SERVER: 172.23.176.1#53(172.23.176.1) (UDP): This identifies the DNS server that provided the answer and the protocol used (UDP).

        ;; WHEN: Thu Jun 13 10:45:58 SAST 2024: This is the timestamp of when the query was made.

        ;; MSG SIZE rcvd: 54: This indicates the size of the DNS message received (54 bytes).

An opt pseudosection can sometimes exist in a dig query. This is due to Extension Mechanisms for DNS (EDNS), which allows for additional features such as larger message sizes and DNS Security Extensions (DNSSEC) support.

If you just want the answer to the question, without any of the other information, you can query dig using +short:

```
dig +short hackthebox.com
104.18.20.126
104.18.21.126
```

## Subdomains

When exploring DNS records, we've primarily focused on the main domain (e.g., example.com) and its associated information. However, beneath the surface of this primary domain lies a potential network of subdomains. These subdomains are extensions of the main domain, often created to organise and separate different sections or functionalities of a website. For instance, a company might use blog.example.com for its blog, shop.example.com for its online store, or mail.example.com for its email services.

Subdomains often host valuable information and resources that aren't directly linked from the main website. This can include:
```
    Development and Staging Environments: Companies often use subdomains to test new features or updates before deploying them to the main site. Due to relaxed security measures, these environments sometimes contain vulnerabilities or expose sensitive information.
    Hidden Login Portals: Subdomains might host administrative panels or other login pages that are not meant to be publicly accessible. Attackers seeking unauthorised access can find these as attractive targets.
    Legacy Applications: Older, forgotten web applications might reside on subdomains, potentially containing outdated software with known vulnerabilities.
    Sensitive Information: Subdomains can inadvertently expose confidential documents, internal data, or configuration files that could be valuable to attackers.
```

Subdomain enumeration is the process of systematically identifying and listing these subdomains. From a DNS perspective, subdomains are typically represented by A (or AAAA for IPv6) records, which map the subdomain name to its corresponding IP address. Additionally, CNAME records might be used to create aliases for subdomains, pointing them to other domains or subdomains. There are two main approaches to subdomain enumeration:

This involves directly interacting with the target domain's DNS servers to uncover subdomains. One method is attempting a DNS zone transfer, where a misconfigured server might inadvertently leak a complete list of subdomains. However, due to tightened security measures, this is rarely successful.

A more common active technique is brute-force enumeration, which involves systematically testing a list of potential subdomain names against the target domain. Tools like dnsenum, ffuf, and gobuster can automate this process, using wordlists of common subdomain names or custom-generated lists based on specific patterns.

This relies on external sources of information to discover subdomains without directly querying the target's DNS servers. One valuable resource is Certificate Transparency (CT) logs, public repositories of SSL/TLS certificates. These certificates often include a list of associated subdomains in their Subject Alternative Name (SAN) field, providing a treasure trove of potential targets.

Another passive approach involves utilising search engines like Google or DuckDuckGo. By employing specialised search operators (e.g., site:), you can filter results to show only subdomains related to the target domain.

Additionally, various online databases and tools aggregate DNS data from multiple sources, allowing you to search for subdomains without directly interacting with the target.

Each of these methods has its strengths and weaknesses. Active enumeration offers more control and potential for comprehensive discovery but can be more detectable. Passive enumeration is stealthier but might not uncover all existing subdomains. Combining both approaches provides a more thorough and effective subdomain enumeration strategy.

## Subdomain Bruteforcing

Subdomain Brute-Force Enumeration is a powerful active subdomain discovery technique that leverages pre-defined lists of potential subdomain names. This approach systematically tests these names against the target domain to identify valid subdomains. By using carefully crafted wordlists, you can significantly increase the efficiency and effectiveness of your subdomain discovery efforts.

```
The process breaks down into four steps:

    Wordlist Selection: The process begins with selecting a wordlist containing potential subdomain names. These wordlists can be:
        General-Purpose: Containing a broad range of common subdomain names (e.g., dev, staging, blog, mail, admin, test). This approach is useful when you don't know the target's naming conventions.
        Targeted: Focused on specific industries, technologies, or naming patterns relevant to the target. This approach is more efficient and reduces the chances of false positives.
        Custom: You can create your own wordlist based on specific keywords, patterns, or intelligence gathered from other sources.
    Iteration and Querying: A script or tool iterates through the wordlist, appending each word or phrase to the main domain (e.g., example.com) to create potential subdomain names (e.g., dev.example.com, staging.example.com).
    DNS Lookup: A DNS query is performed for each potential subdomain to check if it resolves to an IP address. This is typically done using the A or AAAA record type.
    Filtering and Validation: If a subdomain resolves successfully, it's added to a list of valid subdomains. Further validation steps might be taken to confirm the subdomain's existence and functionality (e.g., by attempting to access it through a web browser).
```

There are several tools available that excel at brute-force enumeration:
```
dnsenum 	Comprehensive DNS enumeration tool that supports dictionary and brute-force attacks for discovering subdomains.
fierce 	User-friendly tool for recursive subdomain discovery, featuring wildcard detection and an easy-to-use interface.
dnsrecon 	Versatile tool that combines multiple DNS reconnaissance techniques and offers customisable output formats.
amass 	Actively maintained tool focused on subdomain discovery, known for its integration with other tools and extensive data sources.
assetfinder 	Simple yet effective tool for finding subdomains using various techniques, ideal for quick and lightweight scans.
puredns 	Powerful and flexible DNS brute-forcing tool, capable of resolving and filtering results effectively.
```

dnsenum is a versatile and widely-used command-line tool written in Perl. It is a comprehensive toolkit for DNS reconnaissance, providing various functionalities to gather information about a target domain's DNS infrastructure and potential subdomains. The tool offers several key functions:


    DNS Record Enumeration: dnsenum can retrieve various DNS records, including A, AAAA, NS, MX, and TXT records, providing a comprehensive overview of the target's DNS configuration.
    Zone Transfer Attempts: The tool automatically attempts zone transfers from discovered name servers. While most servers are configured to prevent unauthorised zone transfers, a successful attempt can reveal a treasure trove of DNS information.
    Subdomain Brute-Forcing: dnsenum supports brute-force enumeration of subdomains using a wordlist. This involves systematically testing potential subdomain names against the target domain to identify valid ones.
    Google Scraping: The tool can scrape Google search results to find additional subdomains that might not be listed in DNS records directly.
    Reverse Lookup: dnsenum can perform reverse DNS lookups to identify domains associated with a given IP address, potentially revealing other websites hosted on the same server.
    WHOIS Lookups: The tool can also perform WHOIS queries to gather information about domain ownership and registration details.


Let's see dnsenum in action by demonstrating how to enumerate subdomains for our target, inlanefreight.com. In this demonstration, we'll use the subdomains-top1million-5000.txt wordlist from SecLists, which contains the top 5000 most common subdomains.

`dnsenum --enum inlanefreight.com -f /usr/share/SecLists/Discovery/DNS/subdomains-top1million-110000.txt -r`


```
    dnsenum --enum inlanefreight.com: We specify the target domain we want to enumerate, along with a shortcut for some tuning options ``--enum`.
    -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt: We indicate the path to the SecLists wordlist we'll use for brute-forcing. Adjust the path if your SecLists installation is different.
    -r: This option enables recursive subdomain brute-forcing, meaning that if dnsenum finds a subdomain, it will then try to enumerate subdomains of that subdomain.
```

--------------
The question in this section is:
Using the known subdomains for inlanefreight.com (www, ns1, ns2, ns3, blog, support, customer), find any missing subdomains by brute-forcing possible domain names. Provide your answer with the complete subdomain, e.g., www.inlanefreight.com. 

And I cannot get the dnsenum installed on mac easily. So instead I am just going to enumerate using ffuf.

`ffuf -w /Users/noneya/Useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com -v`

## DNS Zone Transfers

While brute-forcing can be a fruitful approach, there's a less invasive and potentially more efficient method for uncovering subdomains – DNS zone transfers. This mechanism, designed for replicating DNS records between name servers, can inadvertently become a goldmine of information for prying eyes if misconfigured.

A DNS zone transfer is essentially a wholesale copy of all DNS records within a zone (a domain and its subdomains) from one name server to another. This process is essential for maintaining consistency and redundancy across DNS servers. However, if not adequately secured, unauthorised parties can download the entire zone file, revealing a complete list of subdomains, their associated IP addresses, and other sensitive DNS data.



    Zone Transfer Request (AXFR): The secondary DNS server initiates the process by sending a zone transfer request to the primary server. This request typically uses the AXFR (Full Zone Transfer) type.
    SOA Record Transfer: Upon receiving the request (and potentially authenticating the secondary server), the primary server responds by sending its Start of Authority (SOA) record. The SOA record contains vital information about the zone, including its serial number, which helps the secondary server determine if its zone data is current.
    DNS Records Transmission: The primary server then transfers all the DNS records in the zone to the secondary server, one by one. This includes records like A, AAAA, MX, CNAME, NS, and others that define the domain's subdomains, mail servers, name servers, and other configurations.
    Zone Transfer Complete: Once all records have been transmitted, the primary server signals the end of the zone transfer. This notification informs the secondary server that it has received a complete copy of the zone data.
    Acknowledgement (ACK): The secondary server sends an acknowledgement message to the primary server, confirming the successful receipt and processing of the zone data. This completes the zone transfer process.


While zone transfers are essential for legitimate DNS management, a misconfigured DNS server can transform this process into a significant security vulnerability. The core issue lies in the access controls governing who can initiate a zone transfer.

In the early days of the internet, allowing any client to request a zone transfer from a DNS server was common practice. This open approach simplified administration but opened a gaping security hole. It meant that anyone, including malicious actors, could ask a DNS server for a complete copy of its zone file, which contains a wealth of sensitive information.

The information gleaned from an unauthorised zone transfer can be invaluable to an attacker. It reveals a comprehensive map of the target's DNS infrastructure, including:


    Subdomains: A complete list of subdomains, many of which might not be linked from the main website or easily discoverable through other means. These hidden subdomains could host development servers, staging environments, administrative panels, or other sensitive resources.
    IP Addresses: The IP addresses associated with each subdomain, providing potential targets for further reconnaissance or attacks.
    Name Server Records: Details about the authoritative name servers for the domain, revealing the hosting provider and potential misconfigurations.


Fortunately, awareness of this vulnerability has grown, and most DNS server administrators have mitigated the risk. Modern DNS servers are typically configured to allow zone transfers only to trusted secondary servers, ensuring that sensitive zone data remains confidential.

However, misconfigurations can still occur due to human error or outdated practices. This is why attempting a zone transfer (with proper authorisation) remains a valuable reconnaissance technique. Even if unsuccessful, the attempt can reveal information about the DNS server's configuration and security posture.

`dig axfr @nsztm1.digi.ninja zonetransfer.me`

This command instructs dig to request a full zone transfer (axfr) from the DNS server responsible for zonetransfer.me. If the server is misconfigured and allows the transfer, you'll receive a complete list of DNS records for the domain, including all subdomains.

`dig axfr @nsztm1.digi.ninja zonetransfer.me`

zonetransfer.me is a service specifically setup to demonstrate the risks of zone transfers so that the dig command will return the full zone record.

## Virtual Hosts

Once the DNS directs traffic to the correct server, the web server configuration becomes crucial in determining how the incoming requests are handled. Web servers like Apache, Nginx, or IIS are designed to host multiple websites or applications on a single server. They achieve this through virtual hosting, which allows them to differentiate between domains, subdomains, or even separate websites with distinct content.

At the core of virtual hosting is the ability of web servers to distinguish between multiple websites or applications sharing the same IP address. This is achieved by leveraging the HTTP Host header, a piece of information included in every HTTP request sent by a web browser.

The key difference between VHosts and subdomains is their relationship to the Domain Name System (DNS) and the web server's configuration.

Subdomains: These are extensions of a main domain name (e.g., blog.example.com is a subdomain of example.com). Subdomains typically have their own DNS records, pointing to either the same IP address as the main domain or a different one. They can be used to organise different sections or services of a website.

Virtual Hosts (VHosts): Virtual hosts are configurations within a web server that allow multiple websites or applications to be hosted on a single server. They can be associated with top-level domains (e.g., example.com) or subdomains (e.g., dev.example.com). Each virtual host can have its own separate configuration, enabling precise control over how requests are handled.

If a virtual host does not have a DNS record, you can still access it by modifying the hosts file on your local machine. The hosts file allows you to map a domain name to an IP address manually, bypassing DNS resolution.

Websites often have subdomains that are not public and won't appear in DNS records. These subdomains are only accessible internally or through specific configurations. VHost fuzzing is a technique to discover public and non-public subdomains and VHosts by testing various hostnames against a known IP address.

``` apacheconf
# Example of name-based virtual host configuration in Apache
<VirtualHost *:80>
    ServerName www.example1.com
    DocumentRoot /var/www/example1
</VirtualHost>

<VirtualHost *:80>
    ServerName www.example2.org
    DocumentRoot /var/www/example2
</VirtualHost>

<VirtualHost *:80>
    ServerName www.another-example.net
    DocumentRoot /var/www/another-example
</VirtualHost>
```

Here, example1.com, example2.org, and another-example.net are distinct domains hosted on the same server. The web server uses the Host header to serve the appropriate content based on the requested domain name.

The following illustrates the process of how a web server determines the correct content to serve based on the Host header:

Browser Requests a Website: When you enter a domain name (e.g., www.inlanefreight.com) into your browser, it initiates an HTTP request to the web server associated with that domain's IP address.

Host Header Reveals the Domain: The browser includes the domain name in the request's Host header, which acts as a label to inform the web server which website is being requested.

Web Server Determines the Virtual Host: The web server receives the request, examines the Host header, and consults its virtual host configuration to find a matching entry for the requested domain name.

Serving the Right Content: Upon identifying the correct virtual host configuration, the web server retrieves the corresponding files and resources associated with that website from its document root and sends them back to the browser as the HTTP response.

In essence, the Host header functions as a switch, enabling the web server to dynamically determine which website to serve based on the domain name requested by the browser.

There are three primary types of virtual hosting, each with its advantages and drawbacks:

Name-Based Virtual Hosting: This method relies solely on the HTTP Host header to distinguish between websites. It is the most common and flexible method, as it doesn't require multiple IP addresses. It’s cost-effective, easy to set up, and supports most modern web servers. However, it requires the web server to support name-based virtual hosting and can have limitations with certain protocols like SSL/TLS.

IP-Based Virtual Hosting: This type of hosting assigns a unique IP address to each website hosted on the server. The server determines which website to serve based on the IP address to which the request was sent. It doesn't rely on the Host header, can be used with any protocol, and offers better isolation between websites. Still, it requires multiple IP addresses, which can be expensive and less scalable.

Port-Based Virtual Hosting: Different websites are associated with different ports on the same IP address. For example, one website might be accessible on port 80, while another is on port 8080. Port-based virtual hosting can be used when IP addresses are limited, but it’s not as common or user-friendly as name-based virtual hosting and might require users to specify the port number in the URL.

While manual analysis of HTTP headers and reverse DNS lookups can be effective, specialised virtual host discovery tools automate and streamline the process, making it more efficient and comprehensive. These tools employ various techniques to probe the target server and uncover potential virtual hosts.

Several tools are available to aid in the discovery of virtual hosts:

```
gobuster 	A multi-purpose tool often used for directory/file brute-forcing, but also effective for virtual host discovery. 	Fast, supports multiple HTTP methods, can use custom wordlists.
Feroxbuster 	Similar to Gobuster, but with a Rust-based implementation, known for its speed and flexibility. 	Supports recursion, wildcard discovery, and various filters.
ffuf 	Another fast web fuzzer that can be used for virtual host discovery by fuzzing the Host header. 	Customizable wordlist input and filtering options.
```

Gobuster is a versatile tool commonly used for directory and file brute-forcing, but it also excels at virtual host discovery. It systematically sends HTTP requests with different Host headers to a target IP address and then analyses the responses to identify valid virtual hosts.


Target Identification: First, identify the target web server's IP address. This can be done through DNS lookups or other reconnaissance techniques.
Wordlist Preparation: Prepare a wordlist containing potential virtual host names. You can use a pre-compiled wordlist, such as SecLists, or create a custom one based on your target's industry, naming conventions, or other relevant information.


## Certificate Transparancy Logs

In the sprawling mass of the internet, trust is a fragile commodity. One of the cornerstones of this trust is the Secure Sockets Layer/Transport Layer Security (SSL/TLS) protocol, which encrypts communication between your browser and a website. At the heart of SSL/TLS lies the digital certificate, a small file that verifies a website's identity and allows for secure, encrypted communication.

However, the process of issuing and managing these certificates isn't foolproof. Attackers can exploit rogue or mis-issued certificates to impersonate legitimate websites, intercept sensitive data, or spread malware. This is where Certificate Transparency (CT) logs come into play.

Certificate Transparency (CT) logs are public, append-only ledgers that record the issuance of SSL/TLS certificates. Whenever a Certificate Authority (CA) issues a new certificate, it must submit it to multiple CT logs. Independent organisations maintain these logs and are open for anyone to inspect.

Think of CT logs as a global registry of certificates. They provide a transparent and verifiable record of every SSL/TLS certificate issued for a website. This transparency serves several crucial purposes:

Early Detection of Rogue Certificates: By monitoring CT logs, security researchers and website owners can quickly identify suspicious or misissued certificates. A rogue certificate is an unauthorized or fraudulent digital certificate issued by a trusted certificate authority. Detecting these early allows for swift action to revoke the certificates before they can be used for malicious purposes.

Accountability for Certificate Authorities: CT logs hold CAs accountable for their issuance practices. If a CA issues a certificate that violates the rules or standards, it will be publicly visible in the logs, leading to potential sanctions or loss of trust.

Strengthening the Web PKI (Public Key Infrastructure): The Web PKI is the trust system underpinning secure online communication. CT logs help to enhance the security and integrity of the Web PKI by providing a mechanism for public oversight and verification of certificates.

Certificate Transparency logs offer a unique advantage in subdomain enumeration compared to other methods. Unlike brute-forcing or wordlist-based approaches, which rely on guessing or predicting subdomain names, CT logs provide a definitive record of certificates issued for a domain and its subdomains. This means you're not limited by the scope of your wordlist or the effectiveness of your brute-forcing algorithm. Instead, you gain access to a historical and comprehensive view of a domain's subdomains, including those that might not be actively used or easily guessable.

Furthermore, CT logs can unveil subdomains associated with old or expired certificates. These subdomains might host outdated software or configurations, making them potentially vulnerable to exploitation.

In essence, CT logs provide a reliable and efficient way to discover subdomains without the need for exhaustive brute-forcing or relying on the completeness of wordlists. They offer a unique window into a domain's history and can reveal subdomains that might otherwise remain hidden, significantly enhancing your reconnaissance capabilities.


There are two popular options for searching CT logs:
crt.sh -> Free, easy to use, no registration required. -> Limited filtering and analysis options.

While crt.sh offers a convenient web interface, you can also leverage its API for automated searches directly from your terminal. Let's see how to find all 'dev' subdomains on facebook.com using curl and jq:

`curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[]
 | select(.name_value | contains("dev")) | .name_value' | sort -u`


# Fingerprinting

## Fingerprinting

Fingerprinting focuses on extracting technical details about the technologies powering a website or web application. Similar to how a fingerprint uniquely identifies a person, the digital signatures of web servers, operating systems, and software components can reveal critical information about a target's infrastructure and potential security weaknesses. This knowledge empowers attackers to tailor attacks and exploit vulnerabilities specific to the identified technologies.

Fingerprinting serves as a cornerstone of web reconnaissance for several reasons:

Targeted Attacks: By knowing the specific technologies in use, attackers can focus their efforts on exploits and vulnerabilities that are known to affect those systems. This significantly increases the chances of a successful compromise.

Identifying Misconfigurations: Fingerprinting can expose misconfigured or outdated software, default settings, or other weaknesses that might not be apparent through other reconnaissance methods.

Prioritising Targets: When faced with multiple potential targets, fingerprinting helps prioritise efforts by identifying systems more likely to be vulnerable or hold valuable information.

Building a Comprehensive Profile: Combining fingerprint data with other reconnaissance findings creates a holistic view of the target's infrastructure, aiding in understanding its overall security posture and potential attack vectors.

There are several techniques used for web server and technology fingerprinting:

Banner Grabbing: Banner grabbing involves analysing the banners presented by web servers and other services. These banners often reveal the server software, version numbers, and other details.

Analysing HTTP Headers: HTTP headers transmitted with every web page request and response contain a wealth of information. The Server header typically discloses the web server software, while the X-Powered-By header might reveal additional technologies like scripting languages or frameworks.

Probing for Specific Responses: Sending specially crafted requests to the target can elicit unique responses that reveal specific technologies or versions. For example, certain error messages or behaviours are characteristic of particular web servers or software components.

Analysing Page Content: A web page's content, including its structure, scripts, and other elements, can often provide clues about the underlying technologies. There may be a copyright header that indicates specific software being used, for example.

A variety of tools exist that automate the fingerprinting process, combining various techniques to identify web servers, operating systems, content management systems, and other technologies:

Let's apply our fingerprinting knowledge to uncover the digital DNA of our purpose-built host, inlanefreight.com. We'll leverage both manual and automated techniques to gather information about its web server, technologies, and potential vulnerabilities.

Our first step is to gather information directly from the web server itself. We can do this using the curl command with the -I flag (or --head) to fetch only the HTTP headers, not the entire page content.

`curl -I inlanefreight.com`

The output will include the server banner, revealing the web server software and version number:

```
HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:07:44 GMT
Server: Apache/2.4.41 (Ubuntu)
Location: https://inlanefreight.com/
Content-Type: text/html; charset=iso-8859-1
```

In this case, we see that inlanefreight.com is running on Apache/2.4.41, specifically the Ubuntu version. This information is our first clue, hinting at the underlying technology stack. It's also trying to redirect to https://inlanefreight.com/ so grab those banners too

```
HTTP/1.1 301 Moved Permanently
Date: Fri, 31 May 2024 12:12:12 GMT
Server: Apache/2.4.41 (Ubuntu)
X-Redirect-By: WordPress
Location: https://www.inlanefreight.com/
Content-Type: text/html; charset=UTF-8
```

We now get a really interesting header, the server is trying to redirect us again, but this time we see that it's WordPress that is doing the redirection to https://www.inlanefreight.com/

`curl -I https://www.inlanefreight.com`

```
HTTP/1.1 200 OK
Date: Fri, 31 May 2024 12:12:26 GMT
Server: Apache/2.4.41 (Ubuntu)
Link: <https://www.inlanefreight.com/index.php/wp-json/>; rel="https://api.w.org/"
Link: <https://www.inlanefreight.com/index.php/wp-json/wp/v2/pages/7>; rel="alternate"; type="application/json"
Link: <https://www.inlanefreight.com/>; rel=shortlink
Content-Type: text/html; charset=UTF-8
```

A few more interesting headers, including an interesting path that contains wp-json. The wp- prefix is common to WordPress.

Web Application Firewalls (WAFs) are security solutions designed to protect web applications from various attacks. Before proceeding with further fingerprinting, it's crucial to determine if inlanefreight.com employs a WAF, as it could interfere with our probes or potentially block our requests.

To detect the presence of a WAF, we'll use the wafw00f tool. To install wafw00f, you can use pip3:

`pip3 install git+https://github.com/EnableSecurity/wafw00f`

Once it's installed, pass the domain you want to check as an argument to the tool:

`wafw00f inlanefreight.com`

The wafw00f scan on inlanefreight.com reveals that the website is protected by the Wordfence Web Application Firewall (WAF), developed by Defiant.

This means the site has an additional security layer that could block or filter our reconnaissance attempts. In a real-world scenario, it would be crucial to keep this in mind as you proceed with further investigation, as you might need to adapt techniques to bypass or evade the WAF's detection mechanisms.

Nikto is a powerful open-source web server scanner. In addition to its primary function as a vulnerability assessment tool, Nikto's fingerprinting capabilities provide insights into a website's technology stack.

To scan inlanefreight.com using Nikto, only running the fingerprinting modules, execute the following command:
`nikto -h inlanefreight.com -Tuning b`

The -h flag specifies the target host. The -Tuning b flag tells Nikto to only run the Software Identification modules.

Nikto will then initiate a series of tests, attempting to identify outdated software, insecure files or configurations, and other potential security risks.

The reconnaissance scan on inlanefreight.com reveals several key findings:
IPs: The website resolves to both IPv4 (134.209.24.248) and IPv6 (2a03:b0c0:1:e0::32c:b001) addresses.
 Server Technology: The website runs on Apache/2.4.41 (Ubuntu) 
WordPress Presence: The scan identified a WordPress installation, including the login page (/wp-login.php). This suggests the site might be a potential target for common WordPress-related exploits.
Information Disclosure: The presence of a license.txt file could reveal additional details about the website's software components.
Headers: Several non-standard or insecure headers were found, including a missing Strict-Transport-Security header and a potentially insecure x-redirect-by header.

-----------
The questions in this section are:
vHosts needed for these questions:
    app.inlanefreight.local
    dev.inlanefreight.local

Determine the Apache version running on app.inlanefreight.local on the target system. (Format: 0.0.0) 

First I add those hosts to /etc/hosts

Then I run:
`nikto -h app.inlanefreight.local -Tuning b`

Version is 2.4.41

Which CMS is used on app.inlanefreight.local on the target system? Respond with the name only, e.g., WordPress. 

The answer is Joomla. I found this by opening the web page and looking in the source.

On which operating system is the dev.inlanefreight.local webserver running in the target system? Respond with the name only, e.g., Debian. 

`nikto -h dev.inlanefreight.local -Tuning b`

The answer is Ubuntu

# Crawling

## Crawling

## robots.txt

## Well-Known URIs

## Creepy Crawlies

# Search Engine Discovery

## Search Engine Discovery

# Web Archives

## Web Archives

# Automating Recon

## Automating Recon

# Skill Assessment

## Web Recon - Skills Assessment


