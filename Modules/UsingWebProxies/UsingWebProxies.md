# Web Proxy

## Proxy Setup

Both ZAP and Burp Suite have built in browsers to use for Web Proxies. This automatically routes the web traffic through the tool. Burp: Proxy>Intercept>Open Browser Zap: Click Firefox Browser
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

This section briefly covers the decoder tools in Zap and Burp. Burp has a smart decoder tool so it should be easy to use.

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

The Payload Set is the type of words we want to use. We can choose a list of words to test or a bunch of other things.

Payload options is where put our wordlist for a Simple List parameter. You can either pass ina file or add them one by one. We used a list provided for us of common Web-Content directories. `/opt/useful/SecLists/Discovery/Web-Content/common.txt`.

If you want to use a very large wordlist its best to use Runtime file as the Payload Type instead of Simple List, so that Burp Intruder won't have to load the entire wordlist in advance.

We can add options for Payload processing, for instance we used Skip if matches regex and added `^\..*$` to skip any . files.

Finally we customized our attack options to only Grep Match 200 OK as that is what we are interested in.

Running the attack finds that /admin exists, so now we need to check for .html files under the admin directory.

In the end the solution for this test was to run the same attack but with `GET /admin/§val§.html /HTTP/1.1`.

## ZAP Fuzzer

This covers running a fuzz on using the Zap Fuzzer which is MUCH faster than the burp fuzzer because it doesn't have the restrictions on uses. It also has built in lists for Fuzzing and you can add more later. I will be using Zap for any fuzzing I do. 

This test requires us to find the /skills/ directory. Then when found we notice a cookie assigned to a guest user. This cookie is just guest passed into an MD5 hash. So we fuzz that page with common usernames converted to their MD5 hash value. When we look at the responses, we see the response with this cookie `cookie=084e0343a0486ff05530df6c705c8bb4` has a bigger body.

When we rerun that request and check the response, we find `HTB{fuzz1n6_my_f1r57_c00k13}`.

# Web Scanner

## Burp Scanner

This section covers Burp Scanner which is a pro only tool. So I could not follow along, but this tool helps to identify vulnerabilities in web Apps.

## ZAP Scanner

This section covers the Zap web Scanner. 

It starts by covering Zap Spider, which is a web crawler. This will provide a site map of the site and perform a passive scan of all pages found.

Then we can do an active scan of this site. Once we scan it, which takes a long time, it finds a few high alerts including a remote code execution vulnerability. The task on this test is to read /flag.txt.

So to do this we run:
`GET http://94.237.55.163:40627/devtools/ping.php?ip=127.0.0.1%26cat+%2Fflag.txt HTTP/1.1
host: 94.237.55.163:40627
user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36 OPR/102.0.0.0
pragma: no-cache
cache-control: no-cache
referer: http://94.237.55.163:40627/index.php/2021/08/11/customer-support/
content-length: 0
`

And the response shows `HTB{5c4nn3r5_f1nd_vuln5_w3_m155}`

## Extensions

This section covers available extensions in both Burp and Zap. I added an extended decoder/encoder in burp and extended fuzzing lists in Zap.

# Skills Assessment

## Skills Assessment - Using Web Proxies

This section is just test of all the skills learned up to this point.

The first test says `The /lucky.php page has a button that appears to be disabled. Try to enable the button, and then click it to get the flag.`

To solve this, you need to intercept the web request and delete the disable field. This reveals the answer to be `HTB{d154bl3d_bu770n5_w0n7_570p_m3}`

The next test says `The /admin.php page uses a cookie that has been encoded multiple times. Try to decode the cookie until you get a value with 31-characters. Submit the value as the answer.`

To solve this, you need to intercept the web request after opening the admin.php page. Then take the cookie and pass it through a decoder twice. What you find is this cookie is ASCII encoded, then base64 encoded. The solution is `3dac93b8cd250aa8c1a36fffc79a17a`

The next test is `Once you decode the cookie, you will notice that it is only 31 characters long, which appears to be an md5 hash missing its last character. So, try to fuzz the last character of the decoded md5 cookie with all alpha-numeric characters, while encoding each request with the encoding methods you identified above. (You may use the "alphanum-case.txt" wordlist from Seclist for the payload)`

To solve this, you need to pass the previous web requested into Burp Intruder, then set up an attack where you use the previously found cookie as a prefix string and enumerate the over all letters (Upper and Lower case) and numbers. Then you need to pass that new string through an encoder that first does base 64, then ASCII encoding. Afterwards, you need to identify which of the requests responses is of different length, and check that request for the answer. The answer here was `HTB{burp_1n7rud3r_n1nj4!}`

The final test is `You are using the 'auxiliary/scanner/http/coldfusion_locale_traversal' tool within Metasploit, but it is not working properly for you. You decide to capture the request sent by Metasploit so you can manually verify it and repeat it. Once you capture the request, what is the 'XXXXX' directory being called in '/XXXXX/administrator/..'?`

To solve this, all you have to do is run msfconsole, and run 
`auxiliary/scanner/http/coldfusion_locale_traversal?

set RHOSTS IP

set RPORT PORT

run`

The result is
`GET /CFIDE/administrator/index.cfm HTTP/1.1
Host: IP:PORT
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/118.0
Connection: close
`

And the Answer is `CFIDE`
