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

## Determine Login Parameters

## Login Form Attacks

# Service Authentication Attacks

## Personalized Wordlists

## Service Authentication Brute Forcing

# Skills Assessment

## Skills Assessment - Website

## Skills Assessment - Service Login
