# Intro

## Intro

A Brute Force attack is a method of attempting to guess passwords or keys by automated probing. An example of a brute-force attack is password cracking. Passwords are usually not stored in clear text on the systems but as hash values.

Here is a small list of files that can contain hashed passwords:

```
Windows 	Linux
unattend.xml 	shadow
sysprep.inf 	shadow.bak
SAM 		password
```

Since the password cannot be calculated backward from the hash value, the brute force method determines the hash values belonging to the randomly selected passwords until a hash value matches the stored hash value. In this case, the password is found. This method is also called offline brute-forcing. This module will focus on online brute-forcing and explicitly deal with the websites' login forms.

On most websites, there is always a login area for administrators, authors, and users somewhere. Furthermore, usernames are often recognizable on the web pages, and complex passwords are rarely used because they are difficult to remember. Therefore it is worth using the online brute forcing method after a proper enumeration if we could not identify any initial foothold.

There are many tools and methods to utilize for login brute-forcing, like:
```
Ncrack
wfuzz
medusa
patator
hydra 
```

In this module, we will be mainly using hydra, as it is one of the most common and reliable tools available.

# Basic HTTP Auth Brute Forcing

## Password Attacks

We found an unusual host on the network during our black box penetration test and had a closer look at it. We discovered a web server on it that is running on a non-standard port. Many web servers or individual contents on the web servers are still often used with the Basic HTTP AUTH scheme. Like in our case, we found such a webserver with such a path, which should arouse some curiosity.

The HTTP specification provides two parallel authentication mechanisms:

    Basic HTTP AUTH is used to authenticate the user to the HTTP server.

    Proxy Server Authentication is used to authenticate the user to an intermediate proxy server.

These two mechanisms work very similarly as they use requests, response status codes, and response headers. However, there are differences in the status codes and header names used.

The Basic HTTP Authentication scheme uses user ID and password for authentication. The client sends a request without authentication information with its first request. The server's response contains the WWW-Authenticate header field, which requests the client to provide the credentials. This header field also defines details of how the authentication has to take place. The client is asked to submit the authentication information. In its response, the server transmits the so-called realm, a character string that tells the client who is requesting the data. The client uses the Base64 method for encoding the identifier and password. This encoded character string is transmitted to the server in the Authorization header field.

As we don't have any credentials, nor do we have any other ports available, and no services or information about the webserver to be able to use or attack, the only option left is to utilize password brute-forcing.

There are several types of password attacks, such as:
Dictionary attack
Brute force
Traffic interception
Man In the Middle
Key Logging
Social engineering

A Brute Force Attack does not depend on a wordlist of common passwords, but it works by trying all possible character combinations for the length we specified. For example, if we specify the password's length as 4, it would test all keys from aaaa to zzzz, literally brute forcing all characters to find a working password.

However, even if we only use lowercase English characters, this would have almost half a million permutations -26x26x26x26 = 456,976-, which is a huge number, even though we only have a password length of 4.

Once the password length starts to increase, and we start testing for mixed casings, numbers, and special characters, the time it would take to brute force, these passwords can take millions of years.

All of this shows that relying completely on brute force attacks is not ideal, and this is especially true for brute-forcing attacks that take place over the network, like in hydra.
That is why we should consider methods that may increase our odds of guessing the correct password, like Dictionary Attacks.

A Dictionary Attack tries to guess passwords with the help of lists. The goal is to use a list of known passwords to guess an unknown password. This method is useful whenever it can be assumed that passwords with reasonable character combinations are used.

Luckily, there is a huge number of passwords wordlist, consisting of the most commonly used passwords found in tests and database leaks.

We can check out the SecLists repo for wordlists, as it has a huge variety of wordlists, covering many types of attacks.
We can find password wordlists in our PwnBox in /opt/useful/SecLists/Passwords/, and username wordlists in /opt/useful/SecLists/Usernames/.

```
Attack 	Description
Online Brute Force Attack 	Attacking a live application over the network, like HTTP, HTTPs, SSH, FTP, and others
Offline Brute Force Attack 	Also known as Offline Password Cracking, where you attempt to crack a hash of an encrypted password.
Reverse Brute Force Attack 	Also known as username brute-forcing, where you try a single common password with a list of usernames on a certain service.
Hybrid Brute Force Attack 	Attacking a user by creating a customized password wordlist, built using known intelligence about the user or the service.
```

## Default Passwords

Default passwords are a commonly made for testing and often can be forgotten. These passwords frequently are easy to guess as people tend to make things as simple as possible to remember them easily.

As we saw when we visited the website, it prompted the Basic HTTP Authentication form to input the username and password. Basic HTTP Authentication usually responses with an HTTP 401 Unauthorized response code.

Hydra is a handy tool for Login Brute Forcing.

We can run hydra -h to see some of the flags it takes and how it can be used.

Since in the provided example we don't know which user to brute force, we will have to brute force both.

We can either provide different wordlists for the usernames and passwords and iterate over all possible username and password combinations. However, we should keep this as a last resort.

It is very common to find pairs of usernames and passwords used together, especially when default service passwords are kept unchanged. That is why it is better to always start with a wordlist of such credential pairs -e.g. test:test-, and scan all of them first.

SecLists/Passwords/Default-Credentials contains a list of default credentials we can use and in this case we will use ftp-betterdefaultpasslist.txt.

The flags for hydra we will use are -C (Combined Credentials Wordlist), SERVER_IP, -s PORT, http-get (the request method), and / (Target Path).

The command looks like `hydra -C /opt/useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt 178.211.23.155 -s 31099 http-get /`

The question in this section is:
Using the technique you learned in this section, try attacking the IP shown above. What are the credentials used? 

Running `hydra -C ../SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-get` gets the answer. 

Servers.txt contained 94.237.53.3:33944

## Username Brute Force

Now that we know the basics we can try another usage with different wordlists for usernames and passwords.
One of the most commonly used password wordlists is rockyou.txt, which has over 14 million unique passwords, sorted by how common they are, collected from online leaked databases of passwords and usernames. Basically, unless a password is truly unique, this wordlist will likely contain it. Rockyou.txt

We can find it here: SecLists/Passwords/Leaked-Databases/rockyou.txt.

As for our usernames we will use: SecLists/Usernames/Names/names.txt

We can use the -L flag for the usernames wordlist and the -P flag for the passwords. 

We can also tell hydra to stop once it finds a valid login with -f.

WE can also add the -u flag so that it tries all users on each password.

If we run this against our example, it will find a valid answer, but we will quickly realize it takes a long time.

f we were to only brute force the username or password, we could assign a static username or password with the same flag but lowercase. For example, we can brute force passwords for the test user by adding -l test, and then adding a password word list with -P rockyou.txt.

Since we already found the password in the previous section, we may statically assign it with the "-p" flag, and only brute force for usernames that might use this password.

The question in this section:
Try running the same exercise on the question from the previous section, to learn how to brute force for users. (Not really a question)

The answer to this was literally the same answer as last time...

# Web Forms Brute Forcing

## Hydra Modules

On the page we just brute forced, tjere is an admin panel. To cause as little network traffic as possible, it is recommended to try the top 10 most popular administrators' credentials, such as admin:admin.

If these don't work, we can resort to a method called password spraying. This method uses already found, guessed or decrypted passwords across multiple accounts. Since we have been redirected to this panel, that user might have access here as well.

### Brute Forcing Forms

Hydra provides many different types of requests we can use to brute force different services. If we use hydra -h, we should be able to list supported services. 

In this situation there are only two types of http modules interesting for us:

    http[s]-{head|get|post}
    http[s]-post-form

The 1st module serves for basic HTTP authentication, while the 2nd module is used for login forms, like .php or .aspx and others.

Since the file extension is ".php" we should try the http[s]-post-form module. To decide which module we need, we have to determine whether the web application uses GET or a POST form. We can test it by trying to log in and pay attention to the URL. If we recognize that any of our input was pasted into the URL, the web application uses a GET form. Otherwise, it uses a POST form.

Based on the URL scheme at the beginning, we can determine whether this is an HTTP or HTTPS post-form. If our target URL shows http, in this case, we should use the http-post-form module.

To find out how to use the http-post-form module, we can use the "-U" flag to list the parameters it requires and examples of usage:
`hydra http-post-form -U`

```
Examples:
 "/login.php:user=^USER^&pass=^PASS^:incorrect"
```

In summary, we need to provide three parameters, separated by :, as follows:

    URL path, which holds the login form
    POST parameters for username/password
    A failed/success login string, which lets hydra recognize whether the login attempt was successful or not


For the first parameter, we know the URL path is:
/login.php
The second parameter is the POST parameters for username/passwords:
/login.php:[user parameter]=^USER^&[password parameter]=^PASS^
The third parameter is a failed/successful login attempt string. We cannot log in, so we do not know how the page would look like after a successful login, so we cannot specify a success string to look for.
/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:[FAIL/SUCCESS]=[success/failed string]

To make it possible for hydra to distinguish between successfully submitted credentials and failed attempts, we have to specify a unique string from the source code of the page we're using to log in. Hydra will examine the HTML code of the response page it gets after each attempt, looking for the string we provided.

We can specify two different types of analysis that act as a Boolean value.
```
Type 	Boolean Value 	Flag
Fail 	FALSE 	F=html_content
Success 	TRUE 	S=html_content
```

If we provide a fail string, it will keep looking until the string is not found in the response. Another way is if we provide a success string, it will keep looking until the string is found in the response.

Since we cannot log in to see what response we would get if we hit a success, we can only provide a string that appears on the logged-out page to distinguish between logged-in and logged-out pages.
So, let's look for a unique string so that if it is missing from the response, we must have hit a successful login. This is usually set to the error message we get upon a failed login, like Invalid Login Details. However, in this case, it is a little bit trickier, as we do not get such an error message. So is it still possible to brute force this login form?

We can take a look at our login page and try to find a string that only shows in the login page, and not afterwards. For example, one distinct string is Admin Panel: 

So, we may be able to use Admin Panel as our fail string. However, this may lead to false-positives because if the Admin Panel also exists in the page after logging in, it will not work, as hydra will not know that it was a successful login attempt.

A better strategy is to pick something from the HTML source of the login page.
What we have to pick should be very unlikely to be present after logging in, like the login button or the password field. Let's pick the login button, as it is fairly safe to assume that there will be no login button after logging in, while it is possible to find something like please change your password after logging in.

We see it in a couple of places as title/header, and we find our button in the HTML form shown above. We do not have to provide the entire string, so we will use <form name='login', which should be distinct enough and will probably not exist after a successful login.

So, our syntax for the http-post-form should be as follows:

`"/login.php:[user parameter]=^USER^&[password parameter]=^PASS^:F=<form name='login'"`

## Determine Login Parameters

One of the easiest ways to capture a form's parameters is through using a browser's built in developer tools. For example, we can open firefox within PwnBox, and then bring up the Network Tools with [CTRL + SHIFT + E].

Once we do, we can simply try to login with any credentials (test:test) to run the form, after which the Network Tools would show the sent HTTP requests. Once we have the request, we can simply right-click on one of them, and select Copy > Copy POST data:

This would give us the following POST parameters:
username=test&password=test

Another option would be to used Copy > Copy as cURL, which would copy the entire cURL command, which we can use in the Terminal to repeat the same HTTP request:

`atutko@htb[/htb]$ curl 'http://178.128.40.63:31554/login.php' -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://178.128.40.63:31554' -H 'DNT: 1' -H 'Connection: keep-alive' -H 'Referer: http://178.128.40.63:31554/login.php' -H 'Cookie: PHPSESSID=8iafr4t6c3s2nhkaj63df43v05' -H 'Upgrade-Insecure-Requests: 1' -H 'Sec-GPC: 1' --data-raw 'username=test&password=test'`

As we can see, this command also contains the parameters --data-raw 'username=test&password=test'.

In case we were dealing with a web page that sends many HTTP requests, it may be easier to use Burp Suite in order to go through all sent HTTP requests, and pick the ones we are interested in.

## Login Form Attacks

Let's try to use the ftp-betterdefaultpasslist.txt list with the default credentials to test if one of the accounts is registered in the web application.

`hydra -C ../SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`

Since the brute force attack failed using default credentials, we can try to brute force the web application form with a specified user. Often usernames such as admin, administrator, wpadmin, root, adm, and similar are used in administration panels and are rarely changed. Knowing this fact allows us to limit the number of possible usernames. The most common username administrators use is admin. In this case, we specify this username for our next attempt to get access to the admin panel.

`hydra -l admin -P ../SecLists/Passwords/Leaked-Databases/rockyou-75.txt -f -M servers.txt http-post-form "/login.php:username=^USER^&password=^PASS^:F=<form name='login'"`

Running this gets us a valid login. Then when we login the flag is displayed on the page.

The question in this section:
Using what you learned in this section, try attacking the '/login.php' page to identify the password for the 'admin' user. Once you login, you should find a flag. Submit the flag as the answer

Like I said we already got this answer.

# Service Authentication Attacks

## Personalized Wordlists

To create a personalized wordlist for the user, we will need to collect some information about them. As our example here is a known public figure, we can check out their [Wikipedia page](https://en.wikipedia.org/wiki/Bill_Gates) or do a basic Google search to gather the necessary information. Even if this was not a known figure, we can still carry out the same attack and create a personalized wordlist for them. All we need to do is gather some information about them, which is discussed in detail in the Hashcat module, so feel free to check it out.

Many tools can create a custom password wordlist based on certain information. The tool we will be using is cupp, which is pre-installed in your PwnBox. If we are doing the exercise from our own VM, we can install it with sudo apt install cupp or clone it from the Github repository. Cupp is very easy to use. We run it in interactive mode by specifying the -i argument, and answer the questions, as follows:

And as a result, we get our personalized password wordlist saved as william.txt.

The personalized password wordlist we generated is about 43,000 lines long. Since we saw the password policy when we logged in, we know that the password must meet the following conditions:

    8 characters or longer
    contains special characters
    contains numbers

So, we can remove any passwords that do not meet these conditions from our wordlist. Some tools would convert password policies to Hashcat or John rules, but hydra does not support rules for filtering passwords. So, we will simply use the following commands to do that for us:
``` Bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```
We see that these commands shortened the wordlist from 43k passwords to around 13k passwords, around 70% shorter.

It is still possible to create many permutations of each word in that list. We never know how our target thinks when creating their password, and so our safest option is to add as many alterations and permutations as possible, noting that this will, of course, take much more time to brute force.

Many great tools do word mangling and case permutation quickly and easily, like rsmangler or The Mentalist. These tools have many other options, which can make any small wordlist reach millions of lines long. We should keep these tools in mind because we might need them in other modules and situations.

As a starting point, we will stick to the wordlist we have generated so far and not perform any mangling on it. In case our wordlist does not hit a successful login, we will go back to these tools and perform some mangling to increase our chances of guessing the password.

We should also consider creating a personalized username wordlist based on the person's available details. For example, the person's username could be b.gates or gates or bill, and many other potential variations. There are several methods to create the list of potential usernames, the most basic of which is simply writing it manually.

One such tool we can use is Username Anarchy, which we can clone from GitHub, as follows:
git clone https://github.com/urbanadventurer/username-anarchy.git

This tool has many use cases that we can take advantage of to create advanced lists of potential usernames. However, for our simple use case, we can simply run it and provide the first/last names as arguments, and forward the output into a file, as follows:
./username-anarchy Bill Gates > bill.txt

We should finally have our username and passwords wordlists ready and we could attack the SSH server.

## Service Authentication Brute Forcing

The command used to attack a login service is fairly straightforward. We simply have to provide the username/password wordlists, and add service://SERVER_IP:PORT at the end. As usual, we will add the -u -f flags. Finally, when we run the command for the first time, hydra will suggest that we add the -t 4 flag for a max number of parallel attempts, as many SSH limit the number of parallel connections and drop other connections, resulting in many of our attempts being dropped. Our final command should be as follows:

`hydra -L bill.txt -P william2.txt -u -f -M servers.txt -t 4 ssh`

Running this returns:
host: 83.136.254.223   login: b.gates   password: 4dn1l3M!$

Then when we want to get on the server
`ssh b.gates@83.136.255.150 -p 48493`

The questions in this section are:
Using what you learned in this section, try to brute force the SSH login of the user "b.gates" in the target server shown above. Then try to SSH into the server. You should find a flag in the home dir. What is the content of the flag? 

Once we run the above command to get in. We can just run `cat flag.txt`.

Once you ssh in, try brute forcing the FTP login for the other user. You should find another flag in their home directory. What is the flag? 

To do this we can run:
`ls /home` 
And see there is another user named m.gates.

We notice another user, m.gates. We also notice in our local recon that port 21 is open locally, indicating that an FTP must be available:

`netstat -antp | grep -i list`

Next, we can try brute forcing the FTP login for the m.gates user now.
Note 1: Sometimes administrators test their security measures and policies with different tools. In this case, the administrator of this web server kept "hydra" installed. We can benefit from it and use it against the local system by attacking the FTP service locally or remotely.
Note 2: "rockyou-10.txt" can be found in "/opt/useful/SecLists/Passwords/Leaked-Databases/rockyou-10.txt", which contains 92 passwords in total. This is a shorter version of "rockyou.txt" which includes 14,344,391 passwords.

This server already has this file installed when we ssh in. So we can run:
`hydra -l m.gates -P rockyou-10.txt ftp://127.0.0.1`

Then we get `host: 127.0.0.1   login: m.gates   password: computer`

So we can run `ftp 127.0.0.1`

Then when we use the credentials to log in we can run:
```
dir (to see the files)
get flag.txt (copy the file down)
```
Then we can run quit and leave the ftp.
And cat flag.txt again for the new answer.

# Skills Assessment

## Skills Assessment - Website

The questions in this section are:
When you try to access the IP shown above, you will not have authorization to access it. Brute force the authentication and retrieve the flag. 

To get the answer to this all we have to do is run the below code and we get a valid login.
`hydra -C ../SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-get /`

Once you access the login page, you are tasked to brute force your way into this page as well. What is the flag hidden inside?

Once we are in we see that it is the same as before. It is a post form. So we should be able to use these as our paramters:
`"/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"`

So if we try:
`hydra -C ../SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"`

Nothing. No surprise. We will probably need to find a valid password pair with a big list. 

Running gets the answer: 
hydra -L ../SecLists/Usernames/top-usernames-shortlist.txt -P ../SecLists/Passwords/Leaked-Databases/rockyou-75.txt -f -u -M servers.txt http-post-form "/admin_login.php:user=^USER^&pass=^PASS^:F=<form name='log-in'"

Turns out the user is the same (user) should have tried that and just test passwords. But it worked anyway.

## Skills Assessment - Service Login

The page on this says:
We are given the IP address of an online academy but have no further information about their website. As the first step of conducting a Penetration Testing engagement, we have to determine whether any weak credentials are used across the website and other login services.

Look beyond just default/common passwords. Use the skills learned in this module to gather information about employees we identified to create custom wordlists to attack their accounts.

Attack the web application and submit two flags using the skills we covered in the module sections and submit them to complete this module.

So its safe to assume we will need to use Cupp.

The questions in this section are:
As you now have the name of an employee from the previous skills assessment question, try to gather basic information about them, and generate a custom password wordlist that meets the password policy. Also use 'usernameGenerator' to generate potential usernames for the employee. Finally, try to brute force the SSH server shown above to get the flag. 

From the previous section we know the user's name is Harry Potter. So if we pull up the wiki page of Harry Potter we can get some basic information.

We also know the password requirements are:
    Must be 8 characters or longer
    Must contain numbers
    Must contain special characters

Running Cupp (like `python3 cupp.py -i`, with as much information as we could get from the Wiki, I got Harry.txt. But then I needed to remove the lines that don't match the password requirements. So I ran:

`cat harry.txt | sed -r '/^.{,7}$/d' | sed -r '/[!-/:-@\[-`\{-~]+/!d' | sed -r '/[0-9]+/!d' > Harry.txt`

To get a list of usernames I ran:
`./username-anarchy Harry Potter > potter.txt`

Running: `hydra -L potter.txt -P shortHarry.txt -u -f -M servers.txt -t 4 ssh`

I originally created a much larger list of passwords. But it was taking forever, so I read the hint and it said just use the first name.

This returns the username as harry.potter password H4rry!!!

Once I ssh in, I can just run cat flag.txt

Once you are in, you should find that another user exists in server. Try to brute force their login, and get their flag. 

Once I get connected I can run
`ls /home` and see that g.potter is another user. So I can try and brute force her login too.

I notice in my directory that the rockyou-30.txt file exists (good hint I can use that).

So if I run:
`netstat -antp | grep -i list`
I notice that port 21 is open like in the previous exercise. So lets try to brute force the ftp login.

`hydra -l g.potter -P rockyou-30.txt ftp://127.0.0.1`

We get the login as:
`[21][ftp] host: 127.0.0.1   login: g.potter   password: harry`

So we can just run:
`ftp 127.0.0.1`

And run `get flag.txt`

Then disconnect and run `cat flag.txt`

And thats the end of it.
