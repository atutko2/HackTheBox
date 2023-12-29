# Web Proxy

## Proxy Setup

Both ZAP and Burpe Suite have built in browsers to use for Web Proxies. This automatically routes the web traffic through the tool. Burp: Proxy>Intercept>Open Browser Zap: Click Firefox Browser
Needed to install Certs for Burp Suite and Zap so that I can use Proxies. I then had to add them to firefox under preferences>privacy>view Certificates>Authorities>Import

## Intercepting Web Requests

This section covers how to intercept and begin manipulating web requests. Specifically it shows a command injection via HTTP request. If the http request is not verified in the backend it is possible to bypass the security and inject commands. The example here was intercepting a request to an IP address, then changing the ip field on the request to run ls, to list the contents of the directory. The solution to this challenge was to pass in the command `ip=;cat flag.txt;`

## Interception Responses

This section details how to intercept our response and make changes to the css to be able to input what ever want into the text box instead of changing our input being sent.

## Automatic Modification

This section covers adding rules in the match and replace section in burp to perform the steps we did in the above sections.

## Repeating Requests

This section covers how to use to the proxy repeater. Specifically, you have to make the same request you made in the previous section to the ping search to begin doing command injection. Then you need to send that request to the repeater so that we can easily run other commmands on the same search function. Then we need to do a directory traversal upwards to find the new flag. In the end the solution to this challenge was `ip=;cat ../../../flag.txt;`

## Encoding/Decoding

This section brieflhy covers the decoder tools in Zap and Burp. Burp has a smart decoder tool so it should be easy to use.

## Proxying Tools

This section covers using ProxyChains to be able to send web traffic from command line tools to Burp. It covers setting up ProxyChains for this then also covers using Nmap and Metasploit with this proxy.

Nmap is a tool that is supposed to easily enumerate a host. From the Nmap website:
Nmap ("Network Mapper") is a free and open source utility for network discovery and security auditing. Many systems and network administrators also find it useful for tasks such as network inventory, managing service upgrade schedules, and monitoring host or service uptime. Nmap uses raw IP packets in novel ways to determine what hosts are available on the network, what services (application name and version) those hosts are offering, what operating systems (and OS versions) they are running, what type of packet filters/firewalls are in use, and dozens of other characteristics. It was designed to rapidly scan large networks, but works fine against single hosts.

Metasploit is an open source pentesting framework. https://www.simplilearn.com/what-is-metaspoilt-article

# Web Fuzzer

## Burp Intruder

This section covers how to set up Burp Intruder which is a web fuzzer like ffuf, dirbuster, etc. A fuzzer, fuzz testing or fuzzing is an automated software testing method that injects invalid, malformed, or unexpected inputs into a system to reveal software defects and vulnerabilities.

To set up burp intruder we need to open Burp and go to intruder. We need to set up the target:
Host and Port

We need to set up positions. If we want to set up a check for a web directory, we use `/§DIRECTORY§/` (directory can be anything, we are just checking that pointer with the text passed in e.g. /admin/). This will return 200 OK for existing pages and 404 NOT FOUND for ones that don't exist. And we need to choose an attack type, for this one we choose Sniper.

We need to set up the Payloads, which is the wordlist we will be using for this attack. The payloads get iterated over and tested ono by ono in the Payload Position we chose earlier. 

The Payload Set is the type of words we want to use. We can chose a list of words to test or a bunch of other things.

Payload options is where put our wordlist for a Simple List parameter. You can either pass ina file or add them one by one. We used a list provided for us of common Web-Content directories. `/opt/useful/SecLists/Discovery/Web-Content/common.txt`.

If you want to use a very large wordlist its best to use Runtime file as the Payload Type instead of Simple List, so that Burp Intruder won't have to load the entire wordlist in advance.

We can add options for Payload processing, for instance we used Skip if matches regex and added `^\..*$` to skip any . files.

Finally we customized our attack options to only Grep Match 200 OK as that is what we are interested in.

Running the attack finds that /admin exists, so now we need to check for .html files under the admin directory.

In the end the solution for this test was to run the same attack but with `GET /admin/§val§.html /HTTP/1.1`.

## ZAP Fuzzer

# Web Scanner

## Burp Scanner

## ZAP Scanner

## Extensions

# Skills Assessment

## Skills Assessment - Using Web Proxies
