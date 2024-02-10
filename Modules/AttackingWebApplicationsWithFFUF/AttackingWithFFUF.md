# Introduction

## Introduction

This section just covers that we will be using FFUF (Fuzz Faster You Fool)

## Web Fuzzing

This section gives an overview of what Fuzzing is and what Web Fuzzing is. They give the example that if we were fuzzing a sql injection attack we would provide a list of random characters to see if it will allow for injection. Similarly if we were fuzzing a buffer overflow, we would be providing gradually increasing strings. 

For web fuzzing, we are often fuzzing to find hidden or forgotten pages. So we might be fuzzing the URL with a list of frequently used page names. For this module it seems we will be using the SecLists directory-list-2.3-small.txt.

This can be found at `SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`

# Basic Fuzzing

## Page Fuzzing

This goes over a quick fuzzing example to find directories. It covers some of the parameters you can use with ffuf. The big ones are:
-w is the wordlist
-u is the url 

But there are ways to do filtering. 
-fc filters on response code
-fs filters on response size (i.e. if you know its not a specific size remove it)

There are also matcher options and output options

Use ffuf -h to find all options

We also run a fuzz on the provided instance. There is a question in this section:

In addition to the directory we found above, there is another directory that can be found. What is it? 
Running `ffuf -w ../../SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.252.214:52071/FUZZ` returns 2 directories. The answer to this was forum.

## Directory Fuzzing

In the previous section we found a blog directory, but it was blank. In this section we fuzz to find if there are any actual pages in this directory. The first thing we need to do is determine which file extension the server is using. We could try and guess based on the type of server (e.g Apache maybe .php, IIS might be .asp or .aspx, etc). However, this is clunky. 

We can actually try and fuzz the answer here by looking for a index.(extension) file. If we run `ffuf -w SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://IP:port/blog/indexFUZZ` we find that the index page has a .php extension.

Now that we know the extension we can start fuzzing for other pages using the same list we used in the previous section.
`ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://IP:Port/blog/FUZZ.php`

This returns two pages, one is just the index page again, which is empty, but the other is the home page.
Running `curl http://IP:port/blog/home.php` finds the flag.

## Recursive Fuzzing

This section covers that we can recursively run the commands we have already run to find all of the subdomains. By adding the -recursion flag to ffuf and the -recursion-depth flag to set how far to check we can check if there is any more that we missed. We can also add the -e flag to define the extension we are looking for, this will double the size of our search list because it will check the word, then check again with the extension. Finally we use -v to get the full url of the found page. And I also added -ic to remove the copyright info from our wordlist.

Running `ffuf -w ../SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.53.58:55018/FUZZ -recursion -recursion-depth 1 -e .php -v -ic` we find a page under /forum/flag.php.

Running curl on the URL gets the flag.

# Domain Fuzzing

## DNS Records

This section just covers what DNS is. It also notes that if you add a host to the /etc/hosts file you can connect to an ip on the web using that name. Finally it gives a useful command to add hosts to that file.
`sudo sh -c 'echo "SERVER_IP  academy.htb" >> /etc/hosts'`

## Sub-domain Fuzzing

This section covers finding potential subdomains by using a list of common subdomain names from SecLists.
The test here is:
Try running a sub-domain fuzzing test on 'inlanefreight.com' to find a customer sub-domain portal. What is the full domain of it?

Running `ffuf -w ../SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u https://FUZZ.inlanefreight.com -v` get the answer.

But you can also just gather the name of the domain is customer.inlanefreight.com by the question.

## Vhost Fuzzing

This is a little more in depth a task because VHosts may or may not have a public DNS record. And VHosts could be hosted on the same IP. In order to fuzz for a VHost, we can use the -H flag on ffuf. Like this:
`ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb'`

If we run this we will see that all of the response codes are 200, because we already know the IP exists. However, if the VHost actually exists, it will have a different response size.

## Filtering Results

Since all of the responses in the previous run will be size 900, we need to filter those out to find other potential vhosts.

If we run `ffuf -w /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs 986` it will return the Vhosts that exist.

Running that command returns test as the other vhost.

# Parameter Fuzzing

## Parameter Fuzzing - GET

If we run a recursive enumeration of admin.academy.htb, we find there is a http://admin.academy.htb:PORT/admin/admin.php page. However, we cannot just access this page, it says we don't have access. So we choose to fuze Get Parameters on this URL to perhaps find if we can get access. For this we use `SecLists/Discovery/Web-Content/burp-parameter-names.txt`

Get parameters usually take this form `http://admin.academy.htb:PORT/admin/admin.php?param1=key` so we fuzz on param1

Once again we want to filter our results on response size. 

We do a get a response but all it says is the method is deprecated.

The question for this section is: Using what you learned in this section, run a parameter fuzzing scan on this page. what is the parameter accepted by this webpage? 

Running `ffuf -w ../SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://admin.academy.htb:49949/admin/admin.php?FUZZ=key' -fs 798`

Returns that user is the answer.

## Parameter Fuzzing - POST

For Post fuzzing we cannot just append ? to the URL to begin fuzzing. POST requests are passed in the data field. To do this with FFUF we can use -d parameter. Further more for PHP, it only accepts a specific context type. We can use `-H 'Content-Type: application/x-www-form-urlencoded` for PHP. Finally we want to add the -X field to define it is a POST.

So if we refuzz what we did in the previous section:
`ffuf -w ../SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://admin.academy.htb:49949/admin/admin.php' -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded` -X POST -fs 798`

We find the user result again, but also we see id.

IF we try to run get call using id=key it says invalid id. Next we will try fuzzing this ID.

## Value Fuzzing

Since we discovered that the parameter is ID, we can guess this value is a integer of some kind. But this won't always be the case. Sometimes there will be wordlists for fuzzing these params, and sometimes we will have to create our own. In this case, we create a word list of the numbers from 1 - 1000 using:
`for i in $(seq 1 1000); do echo $i >> ids.txt; done`

If we then run the fuzz we did before on POST params, with that wordlist:
`ffuf -w ids.txt:FUZZ -u 'http://admin.academy.htb:49949/admin/admin.php' -d 'id=FUZZ' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -fs 768`

We quickly find that 73 is a valid ID.

Then we can make a CURL Post request with that value to get the key:
`curl -X POST http://admin.academy.htb/admin/admin.php -d 'id=73'`

The answer is HTB{p4r4m373r_fuzz1n6_15_k3y!}
# Skills Assessment

## Skills Assessment - Web Fuzzing

In the skill assessment for this module we are given an IP address and no more information. We are expected to locate all pages and domains linked to that IP. 

Then we need to see if we can find any active parameters on those pages, and finally retrieve data from the page.

The questsions are:

### Run a sub-domain/vhost fuzzing scan on '*.academy.htb' for the IP shown above. What are all the sub-domains you can identify? (Only write the sub-domain name) 

After adding the IP and academy.htb to /etc/hosts:
Running `ffuf -w ../SecLists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ -u http://academy.htb:31637/ -H 'Host: FUZZ.academy.htb' -fs 985` returns the answer.

The answer was 'archive test faculty'. The reason we only look for vhosts here is because this is not a public box. So there will not be any public subdomains to find.


### Before you run your page fuzzing scan, you should first run an extension fuzzing scan. What are the different extensions accepted by the domains?

After adding the above vhosts to the /etc/hosts file. We can run:
`ffuf -w ../SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://faculty.academy.htb:31637/indexFUZZ`
And run it on the other two vhosts as well.

The answer to this question is: '.php .php7 .phps'


### One of the pages you will identify should say 'You don't have access!'. What is the full page URL?

Running this command on all of the sites identifies the page:
`ffuf -w ../SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://VHOST.academy.htb:PORT/courses/FUZZ -recursion -recursion-depth 1 -e php,phps,.php7 -v -ic -fs 287`

The answer is http://faculty.academy.htb:PORT/courses/linux-security.php7.

### In the page from the previous question, you should be able to find multiple parameters that are accepted by the page. What are they? 

Running `ffuf -w ../SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://faculty.academy.htb:PORT/courses/linux-security.php7?FUZZ=key' -fs 774` returns user as a valid parameter

And running `ffuf -w ../SecLists/Discovery/Web-Content/burp-parameter-names.txt:FUZZ -u 'http://faculty.academy.htb:31637/courses/linux-security.php7' -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -X POST -fs 774` returns user and username

The answer to this is 'user username'

### Try fuzzing the parameters you identified for working values. One of them should return a flag. What is the content of the flag?

We can now do a POST fuzz on username parameter to find the flag. If we run:
` ffuf -w ../SecLists/Usernames/xato-net-10-million-usernames.txt:FUZZ -u 'http://faculty.academy.htb:PORT/courses/linux-security.php7' -d 'username=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -X POST -fs 781`

We get these usernames: harry, Harry, HARRY.

Running: `curl 'http://faculty.academy.htb:PORT/courses/linux-security.php7' -X POST -d "username=harry" -H 'Content-Type: application/x-www-form-urlencoded'` gets the answer.

The answer to this: 'HTB{w3b_fuzz1n6_m4573r}'


