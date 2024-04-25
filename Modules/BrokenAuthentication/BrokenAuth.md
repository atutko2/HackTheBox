# Broken Authentication

## What is Authentication

Authorization is defined as the process of approving or disapproving a request from a given (authenticated) entity. This module will not cover authorization in-depth. Understanding the difference between the two security concepts is vital to approach this module with the right mindset.

Assume that we have encountered a login form while performing a penetration test for our Inlanefreight customer. Nowadays, most companies offer certain services for which their customers have to register and authenticate.

Our goal as third-party assessors is to verify if these login forms are implemented securely and if we can bypass them to gain unauthorized access. There are many different methods and procedures to test login forms. We will discuss the most effective of them in detail throughout this module.

## Overview of Authentication Methods

Multi-Factor Authentication, commonly known as MFA (or 2FA when there are just two factors involved), can result in a much more robust authentication process.

Factors are separated into three different domains:

    something the user knows, for example, a username or password
    something the user has, like a hardware token
    something the user is, usually a biometric fingerprint

When an authentication process requires the entity to send data that belongs to more than one of these domains, it should be considered an MFA process. Single Factor Authentication usually requires something the user knows:

    Username + Password

It is also possible for the requirement to be only something the user has.

Think about a corporate badge or a train ticket. Passing through a turnstile often requires you to swipe a badge that grants you access. In this case, you need no PIN, no identification string, or anything else but a card. This is an edge case because company badges, or train multi-cards, are often used to match a specific user by sending an ID. By swiping, both authorization and a form of authentication are performed.

The most common authentication method for web applications is Form-Based Authentication (FBA). The application presents an HTML form where the user inputs their username and password, and then access is granted after comparing the received data against a backend. After a successful login attempt, the application server creates a session tied to a unique key (usually stored in a cookie). This unique key is passed between the client and the web application on every subsequent communication for the session to be maintained.

Some web apps require the user to pass through multiple steps of authentication. For example, the first step requires entering the username, the second the password, and the third a One-time Password (OTP) token. An OTP token can originate from a hardware device or mobile application that generates passwords. One-time Passwords usually last for a limited amount of time, for example, 30 seconds, and are valid for a single login attempt, hence the name one-time.

It should be noted that multi-step login procedures could suffer from business logic vulnerabilities. For example, Step-3 might take for granted that Step-1 and Step-2 have been completed successfully.

Many applications offer HTTP-based login functionality. In these cases, the application server can specify different authentication schemes such as Basic, Digest, and NTLM. All HTTP authentication schemes revolve around the 401 status code and the WWW-Authenticate response header and are used by application servers to challenge a client request and provide authentication details (Challenge-Response process).

When using HTTP-based authentication, the Authorization header holds the authentication data and should be present in every request for the user to be authenticated.

From a network point of view, the abovementioned authentication methods could be less secure than FBA because every request contains authentication data. For example, to perform an HTTP basic auth login, the browser encodes the username and password using base64. The Authorization header will contain the base64-encoded credentials in every request. Therefore, an attacker that can capture the network traffic in plaintext will also capture credentials. The same would happen if FBA were in place, just not for every request.

Below is an example of the header that a browser sends to fulfill basic authentication.
HTTP Authentication Header
Overview of Authentication Methods

GET /basic_auth.php HTTP/1.1
Host: brokenauth.hackthebox.eu
Cache-Control: max-age=0
Authorization: Basic YWRtaW46czNjdXIzcDQ1NQ==

The authorization header specifies the HTTP authentication method, Basic in this example, and the token: if we decode the string:
Overview of Authentication Methods

YWRtaW46czNjdXIzcDQ1NQ==

as a base64 string, we'll see that the browser authenticated with the credentials: admin:s3cur3p455

Digest and NTLM authentication are more robust because the data transmitted is hashed and could contain a nonce, but it is still possible to crack or reuse a captured token.
Other Forms of Authentication

While uncommon, it is also possible that authentication is performed by checking the source IP address. A request from localhost or the IP address of a well-known/trusted server could be considered legitimate and allowed because developers assumed that nobody but the intended entity would use this IP address.

Modern applications could use third parties to authenticate users, such as SAML. Also, APIs usually require a specific authentication form, often based on a multi-step approach.

Attacks against API authentication and authorization, Single Sign-On, and OAuth share the same foundations as attacks against classic web applications. Nevertheless, these topics are pretty broad and deserve their own module.
Login Example

A typical scenario for home banking authentication starts when an e-banking web application requests our ID, which could be a seven-digit number generated by the e-banking web application itself or a username chosen by the user. Then, on a second page, the application requests a password for the given ID. On a third page, the user must provide an OTP generated by a hardware token or received by SMS on their mobile phone. After providing the authentication details from the above two factors (2FA case), the e-banking web application checks if the ID, password, and OTP are valid.

## Overview of Attacks Against Authentication

Authentication attacks can take place against a total of three domains. These three domains are divided into the following categories:

    The HAS domain
    The IS domain
    The KNOWS domain

### Attacking the HAS Domain

Speaking about the three domains described while covering Multi-Factor Authentication, the has domain looks quite plain because we either own a hardware token or do not. Things are more complicated than they appear, though:

    A badge could be cloned without taking it over
    A cryptographic algorithm used to generate One-Time Passwords could be broken
    Any physical device could be stolen

A long-range antenna can easily achieve a working distance of 50cm and clone a classic NFC badge. You may think that the attacker would have to be extremely close to the victim to execute such an attack successfully. Consider how close we are all sitting to each other when using public transport or waiting at a store queue, and you will probably change your mind. Multiple people are within reach to perform such a cloning attack every day.

Imagine that you are having a quick lunch at a bar near the office. You do not even notice an attacker that walks past your seat because you are preoccupied with an urgent work task. They just cloned the badge you keep in your pocket!!! Minutes later, they transfer your badge information into a clean token and use it to enter your company’s building while still eating lunch.

It is clear that cloning a corporate badge is not that difficult, and the consequences could be severe.


### Attacking the IS Domain

You may think that the is domain is the most difficult to attack. If a person relies on “something” to prove their identity and this “something” is compromised, they lose the unique way of proving their identity since there is no way one can change the way they are. Retina scan, fingerprint readers, facial recognition have been all proved to be breakable. All of them can be broken through a third-party leak, a high-definition picture, a skimmer, or even an evil maid that steals the right glass.

Companies that sell security measures based on the is domain state that they are incredibly secure. In August 2019, a company that builds biometric smart locks managed via a mobile or web application was breached. The company used fingerprints or facial recognition to identify authorized users. The breach exposed all fingerprints and facial patterns, including usernames and passwords, grants, and registered users' addresses. While users can easily change their password and mitigate the issue, anybody who can reproduce fingerprints or facial patterns will still be able to unlock and manage these smart locks.

### Attacking the KNOWS Domain

The knows domain is the one we will dig into in this module. It is the simplest one to understand, but we should thoroughly dive into every aspect because it is also the most widespread. This domain refers to things a user knows, like a username or a password. In this module, we will work against FBA only. Keep in mind that the same approach could be adapted to HTTP authentication implementations.

# Login Brute Forcing

## Default Credentials

Long story short, Default Credentials are very common.

When we try to find default or weak credentials, we prefer using automated tools like ffuf, wfuzz, or custom Python scripts, but we could also do the same by hand or using a proxy such as Burp/ZAP. We encourage you to test all methods to become familiar with both automated tools and scripting.

The question in this section is:
Inspect the login page and perform a bruteforce attack. What is the valid username? 

To do this I used:
`hydra -C /Users/noneya/Useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-post-form "/:Username=^USER^&Password=^PASS^:F=Invalid credentials."`

This found no valid passwords.

`hydra -C /Users/noneya/Useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-post-form "/:Username=^USER^&Password=^PASS^:F=Invalid credentials."`

So this isn't going to work. But the page provides a Python script that takes a csv file like the Scada csv file they also provide in this section.

Total red herring too. That script is worthless. And so is the csv. I went to the forums and someone mentioned the username and password is not even in that file. I found this by going (here)[https://www.192-168-1-1-ip.co/router/advantech/advantech-webaccess-browser-based-hmi-and-scada-software/11215/].

One of the worst challenges I have seen on HackTheBox.

## Weak Bruteforce Protections

Before digging into attacks, we must understand the possible protections we could meet during our testing process. Nowadays, there are many different security mechanisms designed to prevent automated attacks. Among the most common are the following.

    CAPTCHA
    Rate Limits

Also, web developers often create their own security mechanisms that make the testing process more “interesting” for us, as these custom security mechanisms may contain bugs that we can exploit. Let’s first familiarize ourselves with common security mechanisms against automated attacks to understand their function and prepare our attacks against them.

### CAPTCHA

CAPTCHA, a widely used security measure named after the Completely Automated Public Turing test to tell Computers and Humans Apart" sentence, can have many different forms. It could require, for example, typing a word presented on an image, hearing a short audio sample and entering what you heard into a form, matching an image to a given pattern, or performing basic math operations.

Even though CAPTCHA has been successfully bypassed in the past, it is still quite effective against automated attacks. An application should at least require a user to solve a CAPTCHA after a few failed attempts. Some developers often skip this protection altogether, and others prefer to present a CAPTCHA after some failed logins to retain a good user experience.

It is also possible for developers to use a custom or weak implementation of CAPTCHA, where for example, the name of the image is made up of the chars contained within the image. Having weak protections is often worse than having no protection since it provides a false sense of security. The image below shows a weak implementation where the PHP code places the image's content into the id field. This type of weak implementation is rare but not unlikely.

As an attacker, we can just read the page's source code to find the CAPTCHA code's value and bypass the protection. We should always read the source.

As developers, we should not develop our own CAPTCHA but rely on a well-tested one and require it after very few failed logins.

### Rate Limiting 

Another standard protection is rate-limiting. Having a counter that increments after each failed attempt, an application can block a user after three failed attempts within 60 seconds and notifies the user accordingly.

A standard brute force attack will not be efficient when rate-limiting is in place. When the tool used is not aware of this protection, it will try username and password combinations that are never actually validated by the attacked web application. In such a case, the majority of attempted credentials will appear as invalid (false negatives). A simple workaround is to teach our tool to understand messages related to rate-limiting and successful and failed login attempts. Download rate_limit_check.py and go through the code. The relevant lines are 10 and 13, where we configure a wait time and a lock message, and line 41, where we do the actual check.

After being blocked, the application could also require some manual operation before unlocking the account. For example, a confirmation code sent by email or a tap on a mobile phone. Rate-limiting does not always impose a cooling-off period. The application may present the user with questions that they must answer correctly before reaccessing the login functionality by the time rate-limiting kicks in.

Most standard rate-limiting implementations that we see nowadays impose a delay after N failed attempts. For example, a user can try to log in three times, and then they must wait 1 minute before trying again. After three additional failed attempts, they must wait 2 minutes and so on.

On the one hand, a regular user could be upset after a delay is imposed, but on the other hand, rate limiting is an excellent form of protection against automated brute force attacks. Note that rate-limiting can be made more robust by gradually increasing the delay and clustering requests by username, source IP address, browser User-Agent, and other characteristics.

We think that every web application has its own requirements for both usability and security that should be thoroughly balanced when developing a rate limit. Applying an early lockout on a crowded and non-critical web application will undoubtedly lead to many requests to the helpdesk. On the other hand, using a rate limit too late could be completely useless.

Mature frameworks have brute-force protections built-in or utilize external plugins/extensions for the same purpose. As a last resort, major webservers like Apache httpd or Nginx could be used to perform rate-limiting on a given login page.

### Insufficient Protections

When an attacker can tamper with data taken into consideration to increase security, they can bypass all or some protections. For example, changing the User-Agent header is easy. Some web applications or web application firewalls leverage headers like X-Forwarded-For to guess the actual source IP address. This is done because many internet providers, mobile carriers, or big corporations usually “hide” users behind NAT. Blocking an IP address without the help of a header like X-Forwarded-For may result in blocking all users behind the specific NAT.

A simple vulnerable example could be:

``` PHP
<?php
// get IP address
if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']))[0];
} else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['HTTP_CLIENT_IP']))[0];
} else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
	$realip = array_map('trim', explode(',', $_SERVER['REMOTE_ADDR']))[0];
}

echo "<div>Your real IP address is: " . htmlspecialchars($realip) . "</div>";
?>
```

CVE-2020-35590 is related to a WordPress plugin vulnerability similar to the one showcased in the snippet above. The plugin’s developers introduced a security improvement that would block a login attempt from the same IP address. Unfortunately, this security measure could be bypassed by crafting an X-Forwarded-For header.

Starting from the script we provided in the previous chapter, we can alter the headers in the provided basic_bruteforce.py script's dict definition at line 9 like this:

``` python
headers = {
  "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36",
  "X-Forwarded-For": "1.2.3.4"
}
```

Some web applications may grant users access based on their source IP address. The behavior we just discussed could be abused to bypass this type of protection.

From a developer's perspective, all security measures should be considered with both user experience and business security in mind. A bank can impose a user lockout that requires a phone call to be undone. A bank can also avoid CAPTCHA because of the need for a second authentication factor (OTP on a USB dongle or via SMS, for example). However, an e-magazine should carefully consider every security protection to achieve a good user experience while retaining a strong security posture.

In no case should a web application rely on a single, tamperable element as a security protection. There is no reliable way to identify the actual IP address of a user behind a NAT, and every bit of information used to tell visitors apart can be tampered with. Therefore, developers should implement protections against brute force attacks that slow down an attacker as much as possible before resorting to user lockout. Slowing things down can be achieved through more challenging CAPTCHA mechanisms, such as CAPTCHA that changes its format at every page load, or CAPTCHA chained with a personal question that we user has answered before. That said, the best solution would probably be to use MFA.

The questions in this section are:

Observe the web application based at subdirectory /question1/ and infer rate limiting. What is the wait time imposed after an attacker hits the limit? (round to a 10-second timeframe, e.g., 10 or 20) 

40

Work on webapp at URL /question2/ and try to bypass the login form using one of the method showed. What is the flag? 

The page title says Broken Authentication Login - Source IP check. So I would guess changing that forward header is part of this question.

I don't see any rate limiting on this page. And no obvious captcha. 

Try `hydra -C /Users/noneya/Useful/SecLists/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt -M servers.txt http-post-form "/question2/:userid=^USER^&passwd=^PASS^&submit=submit:F=Invalid credentials."` fails to find any valid passwords.

I updated the python script in this section to print the result of the requests it makes. Then updated the headers, and ran it with the password list it calls out. This worked.

## Brute Forcing Usernames

Username enumeration is frequently overlooked, probably because it is assumed that a username is not private information. When you write a message to another user, we commonly presume we know their username, email address, etc. The same username is oftentimes reused to access other services such as FTP, RDP and SSH, among others. Since many web applications allow us to identify usernames, we should take advantage of this functionality and use them for later attacks.

For example, on Hack The Box, userid and username are different. Therefore, user enumeration is not possible, but a wide range of web applications suffer from this vulnerability.

Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. Having a list of common users gives an attacker some advantages. In addition to achieving good User Experience (UX), coming across random or non-easily-predictable usernames is uncommon. A user will more easily remember their email address or nickname than a computer-generated and (pseudo)random username.

Having a list of valid usernames, an attacker can narrow the scope of a brute force attack or carry out targeted attacks (leveraging OSINT) against support employees or users themselves. Also, a common password could be easily sprayed against valid accounts, often leading to a successful account compromise.

It should be noted that usernames can also be harvested by crawling a web application or using public information, for example, company profiles on social networks.

Protection against username enumeration attacks can have an impact on user experience. A web application revealing that a username exists or not may help a legitimate user identify that they failed to type their username correctly, but the same applies to an attacker trying to determine valid usernames. Even well-known and mature web frameworks, like WordPress, suffer from user enumeration because the development team chose to have a smoother UX by lowering the framework’s security level a bit. You can refer to this ticket for the entire story

We can see the response message after submitting a non-existent username stating that the entered username is unknown.

In the second example, we can see the response message after submitting a valid username (and a wrong password) stating that the entered username exists, but the password is incorrect.

The difference is clear. On the first try, when a non-existent username is submitted, the application shows an empty login input together with an "Unknown username" message. On the second try, when an existing username is submitted (along with an invalid password), the username form field is prefilled with the valid username. The application shows a message clearly stating that the password is wrong (for this valid username).

When a failed login occurs, and the application replies with "Unknown username" or a similar message, an attacker can perform a brute force attack against the login functionality in search of a, "The password you entered for the username X is incorrect" or a similar message. During a penetration test, do not forget to also check for generic usernames such as helpdesk, tech, admin, demo, guest, etc.

SecLists provides an extensive collection of wordlists that can be used as a starting point to mount user enumeration attacks.

Let us try to brute force a web application. We have two ways to see how the web application expects data. One is by inspecting the HTML form, and the other using an intercepting proxy to capture the actual POST request. When we deal with a basic form, there are no significant differences. However, some applications use obfuscated or contrived JavaScript to hide or obscure details. In these cases, the use of an intercepting proxy is usually preferred. By opening the login page and attempting to log in, we can see that the application accepts the userid in the Username field and the password as Password.

We notice that the application replies with an Unknown username message, and we guess that it uses a different message when the username is valid.

We can carry out the brute force attack using wfuzz and a reverse string match against the response text ( --hs "Unknown username," where "hs" should be a mnemonic used for string hiding), using a short wordlist from SecLists. Since we are not trying to find a valid password, we do not care about the Password field, so we will use a dummy one.

`wfuzz -c -z file,/opt/useful/SecLists/Usernames/top-usernames-shortlist.txt -d "Username=FUZZ&Password=dummypass" --hs "Unknown username" http://brokenauthentication.hackthebox.eu/user_unknown.php`

(NOTE, I looked this up and FFUF and WFuzz are essentially the same thing, but WFuzz is faster)

While wfuzz automatically hides any response containing an "Unknown username" message, we notice that "admin" is a valid user (the remaining usernames on the top-username-shortlist.txt wordlist are not valid). If an excellent UX is not a hard requirement, an application should reply with a generic message like "Invalid credentials" for unknown usernames and wrong passwords.

Sometimes a web application may not explicitly state that it does not know a specific username but allows an attacker to infer this piece of information. Some web applications prefill the username input value if the username is valid and known but leave the input value empty or with a default value when the username is unknown. This is quite common on mobile versions of websites and was also the case on the vulnerable WordPress login page we saw earlier. While developing, always try to give the same experience for both failed and granted login: even a slight difference is more than enough to infer a piece of information.

Testing a web application by logging in as an unknown user, we notice a generic error message and an empty login page:

When we try to log in as user "admin", we notice that the input field is pre-filled with the (probably) a valid username, even if we receive the same generic error message:

While uncommon, it is also possible that different cookies are set when a username is valid or not. For example, to check for password attempts using client-side controls, a web application could set and then check a cookie named "failed_login" only when the username is valid. Carefully inspect responses watching for differences in both HTTP headers and the HTML source code.

Some authentication functions may contain flaws by design. One example is an authentication function where the username and password are checked sequentially. Let us analyze the below routine.

``` PHP
<?php
// connect to database
$db = mysqli_connect("localhost", "dbuser", "dbpass", "dbname");

// retrieve row data for user
$result = $db->query('SELECT * FROM users WHERE username="'.safesql($_POST['user']).'" AND active=1');

// $db->query() replies True if there are at least a row (so a user), and False if there are no rows (so no users)
if ($result) {
  // retrieve a row. don't use this code if multiple rows are expected
  $row = mysqli_fetch_row($result);

  // hash password using custom algorithm
  $cpass = hash_password($_POST['password']);
  
  // check if received password matches with one stored in the database
  if ($cpass === $row['cpassword']) {
	echo "Welcome $row['username']";
  } else {
    echo "Invalid credentials.";
  } 
} else {
  echo "Invalid credentials.";
}
?>
```

The code snippet first connects to the database and then executes a query to retrieve an entire row where the username matches the requested one. If there are no results, the function ends with a generic message. When $result is true (the user exists and is active), the provided password is hashed and compared. If the hashing algorithm used is strong enough, timing differences between the two branches will be noticeable. By calculating $cpass using a generic hash_password() function, the response time will be higher than the other case. This small error could be avoided by checking user and password in the same step, having a similar time for both valid and invalid usernames.

Download the script timing.py to witness these types of timing differences and run it against an example web application (timing.php) that uses bcrypt.

```
python3 timing.py /opt/useful/SecLists/Usernames/top-usernames-shortlist.txt

[+] user root took 0.003
[+] user admin took 0.263
[+] user test took 0.005
[+] user guest took 0.003
[+] user info took 0.001
[+] user adm took 0.001
[+] user mysql took 0.001
[+] user user took 0.001
[+] user administrator took 0.001
[+] user oracle took 0.001
[+] user ftp took 0.001
[+] user pi took 0.001
[+] user puppet took 0.001
[+] user ansible took 0.001
[+] user ec2-user took 0.001
[+] user vagrant took 0.001
[+] user azureuser took 0.001
```

Given that there could be a network glitch, it is easy to identify "admin" as a valid user because it took way more time than other tested users. If the algorithm used was a fast one, time differences would be smaller, and an attacker could have a false positive because of a network delay or CPU load. However, the attack is still possible by repeating a large number of requests to create a model. While we could assume that a modern application hashes passwords using a robust algorithm to make a potential offline brute force attack as slow as possible, it is possible to infer information even if it uses a fast algorithm like MD5 or SHA1.

When LinkedIn's userbase was leaked in 2012, InfoSec professionals started a debate about SHA1 being used as a hashing algorithm for users' passwords. While SHA1 did not break during those days, it was known as an insecure hashing solution. Infosec professionals started arguing about the choice to use SHA1 instead of more robust hashing algorithms like scrypt, bcrypt or PBKDF (or argon2).

While it is always preferable to use a more robust algorithm than a weaker one, an architecture engineer should also keep in mind the computational cost. This very basic Python script helps shed some light on the issue:

``` python
import scrypt
import bcrypt
import datetime
import hashlib

rounds = 100
salt = bcrypt.gensalt()

t0 = datetime.datetime.now()

for x in range(rounds):
    scrypt.hash(str(x).encode(), salt)

t1 = datetime.datetime.now()

for x in range(rounds):
    hashlib.sha1(str(x).encode())

t2 = datetime.datetime.now()

for x in range(rounds):
    bcrypt.hashpw(str(x).encode(), salt)

t3 = datetime.datetime.now()

print("sha1:   {}\nscrypt: {}\nbcrypt: {}".format(t2-t1,t1-t0,t3-t2))
```

Keep in mind that modern best practices highly recommend using more robust algorithms, which results in an increment of CPU time and RAM usage. If we focus on bcrypt for a minute, running the script above on an 8core eighth-gen i5 gives the following results.

```
python3 hashtime.py

sha1:   0:00:00.000082
scrypt: 0:00:03.907575
bcrypt: 0:00:22.660548
```

Let us add some context by going over a rough example:

    LinkedIn has ~200M daily users, which means ~24 logins per second (we are not excluding users with a remember-me token).

If they used a robust algorithm like bcrypt, which used 0.23 seconds for each round on our test machine, they would need six servers just to let people log in. This does not sound like a big issue for a company that runs thousands of servers, but it would require an overhaul of the architecture.

Reset forms are often less well protected than login ones. Therefore, they very often leak information about a valid or invalid username. Like we have already discussed, an application that replies with a "You should receive a message shortly" when a valid username has been found and "Username unknown, check your data" for an invalid entry leaks the presence of registered users.

This attack is noisy because some valid users will probably receive an email that asks for a password reset. That being said, these emails frequently do not get proper attention from end-users.

By default, a registration form that prompts users to choose their username usually replies with a clear message when the selected username already exists or provides other “tells” if this is the case. By abusing this behavior, an attacker could register common usernames, like admin, administrator, tech, to enumerate valid ones. A secure registration form should implement some protection before checking if the selected username exists, like a CAPTCHA.

One interesting feature of email addresses that many people do not know or do not have ready in mind while testing is sub-addressing. This extension, defined at RFC5233, says that any +tag in the left part of an email address should be ignored by the Mail Transport Agent (MTA) and used as a tag for sieve filters. This means that writing to an email address like student+htb@hackthebox.eu will deliver the email to student@hackthebox.eu and, if filters are supported and properly configured, will be placed in folder htb. Very few web applications respect this RFC, which leads to the possibility of registering almost infinite users by using a tag and only one actual email address.

Of course, this attack is quite loud and should be carried out with great care.

In web applications with fewer UX requirements like, for example, home banking or when there is the need to create many users in a batch, we may see usernames created sequentially.

While uncommon, you may run into accounts like user1000, user1001. It is also possible that "administrative" users have a predictable naming convention, like support.it, support.fr, or similar. An attacker could infer the algorithm used to create users (incremental four digits, country code, etc.) and guess existing user accounts starting from some known ones.

The questions in this section are:

Find the valid username on the web app based at the /question1/ subdirectory. PLEASE NOTE: Use the same wordlist for all four questions. 

Trying 

`ffuf -w /Users/noneya/Useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u 'http://94.237.54.170:53374/question1/?Username=FUZZ&Password=a'` 

You see a response with greater size, so I see that puppet is a valid user.

Find the valid username for the web application based at subdirectory /question2/. 

Both the forgot password and create account links on this page dont work, so this is a good hint that this test is either on timing. Or if the output on the page contains the username again.

When I look at the request it has form data looking like:
```
{
	"Username": "test",
	"wronguser": "puppet",
	"count": "1",
	"Password": "test"
}
```

And this is a post form. So I guess the test here is to see if the result of the previous user says wronguser.

There are only 17 users in the list we used last time. I could write a script and use Curl. But I think its easier to just do this check manually.

Going through the list I quickly see:
```
{
	"Username": "administrator",
	"validuser": "ansible",
	"count": "1",
	"Password": "a"
}
```

Find the valid account name for the web application based at subdirectory /question3/. 

This one also doesn't let me use forgot password or create account.

When I look at the form data for this one all I see is:
```
{
	"userid": "adm",
	"passwd": "a"
}
```

This is also a post request. So lets use ffuf.

`ffuf -w /Users/noneya/Useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u 'http://94.237.54.170:53374/question3/' -d 'userid=FUZZ&passwd=a' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

Running this I see a much longer response time for vagrant, and that is in fact the user.

Now find another way to discover the valid username for the web application based at subdirectory /question4/ . 

In this section, the Create Account button works, so I am starting here.

Trying:
`ffuf -w /Users/noneya/Useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZ -u 'http://94.237.54.170:53374/question4/register.php' -d 'userid=FUZZ&email=ad%40email.com&passwd1=a&passwd2=a&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

I see that user has a much larger response size than the others. So thats the user.

## Brute Forcing Passwords

After having success at username enumeration, an attacker is often just one step from the goal of bypassing authentication, and that step is the user’s password. Passwords are the primary, when not the only one, security measure for most applications. Despite its popularity, this measure is not always perceived as important by both end-users and administrators/maintainers. Therefore, the attention it receives is usually not enough. Wikipedia has a page that lists the most common passwords with a leaderboard for every year starting from 2011. If you have a quick look at this table you can see that people are not so careful.

Historically speaking, passwords suffered from three significant issues. The first one lies in the name itself. Very often, users think that a password can be just a word and not a phrase. The second issue is that users mostly set passwords that are easy to remember. Such passwords are usually weak or follow a predictable pattern. Even if a user chooses a more complex password, it will usually be written on a Post-it or saved in cleartext. It is also not that uncommon to find the password written in the hint field. The second password issue gets worse when a frequent password rotation requirement to access enterprise networks comes into play. This requirement usually results in passwords like Spring2020, Autumn2020 or CompanynameTown1, CompanynameTown2 and so forth.

Recently NIST, the National Institute of Standards and Technology refreshed its guidelines around password policy testing, password age requirements, and password composition rules.

The relevant change is:

Verifiers SHOULD NOT impose other composition rules (e.g., requiring mixtures of different character types or prohibiting consecutively repeated characters) for memorized secrets. Verifiers SHOULD NOT require memorized secrets to be changed arbitrarily (e.g., periodically).

Finally, it is a known fact that many users reuse the same password on multiple services. A password leak or compromise on one of them will give an attacker access to a wide range of websites or applications. This attack is known as Credential stuffing and goes hand in hand with wordlist generation, taught in the Cracking Passwords with Hashcat module. A viable solution for storing and using complex passwords is password managers. Sometimes you may come across weak password requirements. This usually happens when there are additional security measures in place. An excellent example of that is ATMs. The password, or better the PIN, is a just sequence of 4 or 5 digits. Pretty weak, but lack of complexity is balanced by a limitation in total attempts (no more than 3 PINs before losing physical access to the device).

### Policy Inference

The chances of executing a successful brute force attack increase after a proper policy evaluation. Knowing what the minimum password requirements are, allows an attacker to start testing only compliant passwords. A web app that implements a strong password policy could make a brute force attack almost impossible. As a developer, always choose long passphrases over short but complex passwords. On virtually any application that allows self-registration, it is possible to infer the password policy by registering a new user. Trying to use the username as a password, or a very weak password like 123456, often results in an error that will reveal the policy (or some parts of it) in a human-readable format.

Policy requirements define how many different families of characters are needed, and the length of the password itself.

Families are:

    lowercase characters, like abcd..z

    uppercase characters, like ABCD..Z

    digit, numbers from 0 to 9

    special characters, like ,./.?! or any other printable one (space is a char!)


It is possible that an application replies with a Password does not meet complexity requirements message at first and reveals the exact policy conditions after a certain number of failed registrations. This is why it is recommended to test three or four times before giving up.

The same attack could be carried on a password reset page. When a user can reset her password, the reset form may leak the password policy (or parts of it). During a real engagement, the inference process could be a guessing game. Since this is a critical step, we are providing you with another basic example. Having a web application that lets us register a new account, we try to use 123456 as a password to identify the policy. The web application replies with a Password does not match minimum requirements message. A policy is obviously in place, but it is not disclosed.

We then start guessing the requirements by registering an account and entering a keyboard walk sequence for the password like Qwertyiop123!@#, which is actually predictable but long and complex enough to match standard policies.

Suppose that the web application accepts such passwords as valid. Now let’s decrease complexity by removing special characters, then numbers, then uppercase characters, and decreasing the length by one character at a time. Specifically, we try to register a new user using Qwertyiop123, then Qwertyiop!@#, then qwertyiop123, and so forth until we have a matrix with the minimum requirements. While testing web applications, also bear in mind that some also limit password length by forcing users to have a password between 8 and 15 characters. This process is prone to error, and it is also possible that some combinations will not be tested while others will be tested twice. For this reason, it is recommended to use a table like this to keep track of our test

Within a few tries, we should be able to infer the policy even if the message is generic. Let us now suppose that this web application requires a string between 8 and 12 characters, with at least one uppercase and lowercase character. We now take a giant wordlist and extract only passwords that match this policy. Unix grep is not the fastest tool but allows us to do the job quickly using POSIX regular expressions. The command below will work against rockyou-50.txt, a subset of the well-known rockyou password leak present in SecLists. This command finds lines have at least one uppercase character ('[[:upper:]]'), and then only lines that also have a lowercase one ('[[:lower:]]') and with a length of 8 and 12 chars ('^.{8,12}$') using extended regular expressions (-E).

`grep '[[:upper:]]' rockyou.txt | grep '[[:lower:]]' | grep -E '^.{8,12}$' | wc -l`

We see that starting from the standard rockyou.txt, which contains more than 14 million lines, we have narrowed it down to roughly 400 thousand. If you want to practice yourself, download the PHP script here and try to match the policy. We suggest keeping the table we just provided handy for this exercise.

### Perform an Actual Bruteforce Attack

Now that we have a username, we know the password policy and the security measures in place, we can start brute-forcing the web application. Please bear in mind that you should also check if an anti-CSRF token protects the form and modify your script to send such a token.


The question in this section is:
Using rockyou-50.txt as password wordlist and htbuser as the username, find the policy and filter out strings that don't respect it. What is the valid password for the htbuser account? 

Using some testing it seems like all it requres is a capital letter and a number.

No length requirements.

So lets grep rockyou-50.txt.

`cat /Users/noneya/Useful/SecLists/Passwords/Leaked-Databases/rockyou-50.txt | grep '[[:upper:]]' | grep '[0-9]' > passwords.txt`

Then we can use ffuf

`ffuf -w ./passwords.txt:FUZZ -u 'http://94.237.53.3:31906/' -d 'userid=htbuser&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

I see that ANGEL1 has a different size. So thats the answer.

## Predictable Reset Token

Reset tokens (in the form of a code or temporary password) are secret pieces of data generated mainly by the application when a password reset is requested. A user must provide it to prove their identity before actually changing their credentials. Sometimes applications require you to choose one or more security questions and provide an answer at the time of registration. If you forgot your password, you could reset it by answering these questions again. We can consider these answers as tokens too.

This function allows us to reset the actual password of the user without knowing the password. There are several ways this can be done, which we will discuss soon.

A password reset flow may seem complicated since it usually consists of several steps that we must understand. Below, we created a basic flow that recaps what happens when a user requests a reset and receives a token by email. Some steps could go wrong, and a process that looks safe can be vulnerable.

If an application lets the user reset her password using a URL or a temporary password sent by email, it should contain a robust token generation function. Frameworks often have dedicated functions for this purpose. However, developers often implement their own functions that may introduce logic flaws and weak encryption or implement security through obscurity.

Some applications create a token using known or predictable values, such as local time or the username that requested the action and then hash or encode the value. This is a poor security practice because a token doesn't need to contain any information from the actual user to be validated and should be a pure-random value. In the case of reversible encoding, it could be enough to decode the token to understand how it is built and forge a valid one.

As penetration testers, we should be aware of these types of poor implementations. We should try to brute force any weak hash using known combinations like time+username or time+email when a reset token is requested for a given user. Take for example this PHP code. It is the logical equivalent of the vulnerability reported as CVE-2016-0783 on Apache OpenMeeting:

``` php
<?php
function generate_reset_token($username) {
  $time = intval(microtime(true) * 1000);
  $token = md5($username . $time);
  return $token;
}
```

It is easy to spot the vulnerability. An attacker that knows a valid username can get the server time by reading the Date header (which is almost always present in the HTTP response). The attacker can then brute force the $time value in a matter of seconds and get a valid reset token. In this example, we can see that a common request leaks date and time.

Let's take as an example the PHP code downloadable here. The application generates a token by creating an md5 hash of the number of seconds since epoch (for demonstration purposes, we just use a time value). Reading the code, we can easily spot a vulnerability similar to the OpenMeeting one. Using the reset_token_time.py script, we could gain some confidence in creating and brute-forcing a time-based token. Download both scripts and try to get the welcome message.

Please bear in mind that any header could be stripped or altered by placing a reverse proxy in front of the application. However, we often have the chance to infer time in different ways. These are the time of a sent or received in-app message, an email header, or last login time, to name a few. Some applications do not check for the token age, giving an attacker plenty of time for a brute force attack. It has also been observed that some applications never invalidate or expire tokens, even if the token has been used. Retaining such a critical component active is quite risky since an attacker could find an old token and use it.

Another bad practice is the use of short tokens. Probably to help mobile users, an application might generate a token with a length of 5/6 numerical characters that sometimes could be easily brute-forced. In reality, there is no need to use a short one because tokens are received mainly by e-mail and could be embedded in an HTTP link that can be validated using a simple GET call like https://127.0.0.1/reset.php?token=any_random_sequence. A token could, therefore, easily be a sequence of 32 characters, for example. Let us consider an application that generates tokens consisting of five digits for the sake of simplicity. Valid token values range from 00000 to 99999. At a rate of 10 checks per second, an attacker can brute force the entire range in about 3 hours.

Also, consider that the same application replies with a Valid token message if the submitted token is valid; otherwise, an Invalid token message is returned. If we wanted to perform a brute force attack against the abovementioned application’s tokens, we could use wfuzz. Specifically, we could use a string match for the case-sensitive string Valid (--ss "Valid"). Of course, if we did not know how the web application replies when a valid token is submitted, we could use a “reverse match” by looking for any response that does not contain Invalid token using --hs "Invalid." Finally, a five-digit integer range can be specified and created in wfuzz using -z range,00000-99999. You can see the entire wfuzz command below.

`wfuzz -z range,00000-99999 --ss "Valid" "https://brokenauthentication.hackthebox.eu/token.php?user=admin&token=FUZZ"`

An attacker could obtain access as a user before the morning coffee by executing the above brute force attack at night. Both the user and a sysadmin that checks logs and network traffic will most probably notice an anomaly, but it could be too late. This edge case may sound unrealistic, but you will be surprised by the lack of security measures in the wild. Always try to brute force tokens during your tests, considering that such an attack is loud and can also cause a Denial of Service, so it should be executed with great care and possibly only after conferring with your client.

Even cryptographically generated tokens could be predictable. It has been observed that some developers try to create their own crypto routine, often resorting to security through obscurity processes. Both cases usually lead to weak token randomness. Also, some cryptographic functions have proven to be less secure. Rolling your own encryption is never a good idea. To stay on the safe side, we should always use modern and well-known encryption algorithms that have been heavily reviewed. A fascinating use case on attacks against weak cryptography is the research performed by by F-Secure lab on OpenCart, published here.

Researchers discovered that the application uses the mt_rand() PHP function, which is known to be vulnerable due to lack of sufficient entropy during the random value generation process. OpenCart uses this vulnerable function to generate all random values, from CAPTCHA to session_id to reset tokens. Having access to some cryptographically insecure tokens makes it possible to identify the seed, leading to predicting any past and future token.

Attacking mt_rand() is not an easy task by any means, but proof of concept attacks have been released here and here. mt_rand() should be therefore used with caution and taking into account the security implications. The OpenCart example was a serious case since an attacker could easily obtain some values generated using mt_rand() through CAPTCHA without even needing a valid user account.

The questions in this section are:
Create a token on the web application exposed at subdirectory /question1/ using the *Create a reset token for htbuser* button. Within an interval of +-1 second a token for the htbadmin user will also be created. The algorithm used to generate both tokens is the same as the one shown when talking about the Apache OpenMeeting bug. Forge a valid token for htbadmin and login by pressing the "Check" button. What is the flag?

Literally nothing I do here seems to work. The hint says to take the time displayed and convert it to epoch time in miliseconds. Then run the script. However, no matter how I try to do this the script fails. I saw some comments online that MacOS doesn't work for this test. But even running it on the PwnBox fails. I even found a script that should work when replaced with the correct epoch time, but that fails too. Giving up here.

Request a reset token for htbuser and find the encoding algorithm, then request a reset token for htbadmin to force a password change and forge a valid temp password to login. What is the flag?

The forgot password page dispays an encoded one time password in Base64. When I decode, it appears to still be encoded, this time in ASCII. Decoding again shows:
htbuser:htbuser@academy.hackthebox.eu:unbreakable

Changing to:
htbadmin:htbadmin@academy.hackthebox.eu:unbreakable and re-encoding in order gets the password.

Then we can just go to the login page put in htbadmin, and the encoded password to get the flag.

# Password Attacks

## Authentication Credentials Handling

By authentication credentials handling, we mean how an application operates on passwords (password reset, password recovery, or password change). A password reset, for example, could be an easy but loud way to bypass authentication.

Speaking about typical web applications, users who forget their password can get a new one in three ways when no external authentication factor is used.

    By requesting a new one that will be sent via email by the application
    By requesting a URL that will allow them to set a new one
    By answering prefilled questions as proof of identity and then setting a new one

As penetration testers, we should always look for logic flaws in "forgot password" and "password change" functionalities, as they may allow us to bypass authentication.

## Guessable Answers

Often web applications authenticate users who lost their password by requesting that they answer one or multiple questions. Those questions, usually presented to the user during the registration phase, are mostly hardcoded and cannot be chosen by them. They are, therefore, quite generic.

Assuming we had found such functionality on a target website, we should try abusing it to bypass authentication. In these cases, the problem, or rather the weak point, is not the function per se but the predictability of questions and the users or employees themselves. It is common to find questions like the below.

    "What is your mother's maiden name?"

    "What city were you born in?"

The first one could be found using OSINT, while the answer to the second one could be identified again using OSINT or via a brute-force attack. Admittedly, answering both questions could be performed without knowing much about the target user.

We discourage the use of security answers because even when an application allows users to choose their questions, answers could still be predictable due to users’ negligence. To raise the security level, a web application should keep repeating the first question until the user answers correctly. This way, an attacker who is not lucky enough to know the first answer or come across a question that can be easily brute-forced on the first shot cannot try the second one. When we find a web application that keeps rotating questions, we should collect them to identify the easiest to brute force and then mount the attack.

Scraping a website could be quite complicated because some web applications scramble form data or use JavaScript to populate forms. Some others keep all question details stored on the server-side. Therefore, we should build a brute force script utilizing a helper, like when there is an Anti-CSRF token present. We prepared a basic web page that rotates questions and a Python template that you can use to experiment with this attack. You can download the PHP file here and Python code here. Take the time to understand how the web application functions fully. We suggest trying manually and then writing your own script. Use someone else’s script only as a last resort.

The question in this section is:
Reset the htbadmin user's password by guessing one of the questions. What is the flag? 

This page shows a script we could try to use to brute force this, but going through the questions, there was one about the favorite color. So I just sent the request to repeater in Burp and tried every color. The answer was pink.

## Username Injection

When trying to understand the high-level logic behind a reset form, it is unimportant if it sends a token, a temporary password, or requires the correct answer. At a high level, when a user inputs the expected value, the reset functionality lets the user change the password or pass the authentication phase. The function that checks if a reset token is valid and is also the right one for a given account is usually carefully developed and tested with security in mind. However, it is sometimes vulnerable during the second phase of the process, when the user resets the password after the first login has been granted.

Imagine the following scenario. After creating an account of our own, we request a password reset. Suppose we come across a form that behaves as follows.

We can try to inject a different username and/or email address, looking for a possible hidden input value or guessing any valid input name. It has been observed that some applications give precedence to received information against information stored in a session value.

An example of vulnerable code looks like this (the $_REQUEST variable contains both $_GET and $_POST):
``` php
<?php
  if isset($_REQUEST['userid']) {
	$userid = $_REQUEST['userid'];
  } else if isset($_SESSION['userid']) {
	$userid = $_SESSION['userid'];
  } else {
	die("unknown userid");
  }
```
This could look weird at first but think about a web application that allows admins or helpdesk employees to reset other users' passwords. Often, the function that changes the password is reused and shares the same codebase with the one used by standard users to change their password. An application should always check authorization before any change. In this case, it has to check if the user has the rights to modify the password for the target user. With this in mind, we should enumerate the web application to identify how it expects the username or email field during the login phase, when there are messages or a communication exchange, or when we see other users' profiles. Having collected a list of all possible input field names, we will attack the application. The attack will be executed by sending a password reset request while logged in with our user and injecting the target user's email or username through the possible field names (one at a time).

We brute-forced the username and password on a web application that uses userid as a field name during the login process in previous exercises. Let us keep this field as an identifier of the user and operate on it. A standard request looks as follows.

If you tamper with the request by adding the userid field, you can change the password for another user.

As we can see, the application replies with a success message.

When we have a small number of fields and user/email values to test, you can mount this attack using an intercepting proxy. If you have many of them, you can automate the attack using any fuzzer or a custom script. We prepared a small playground to let you test this attack. You can download the PHP script here and Python script here. Take your time to study both files, then try to replicate the attack we showed.

The question in this section is:
Login with the credentials "htbuser:htbuser" and abuse the reset password function to escalate to "htbadmin" user. What is the flag?

When we reset the password for htbuser we see the submit content is:
oldpasswd=htbuser&newpasswd=password1&confirm=password1&&submit=doreset

We can send this to repeater and change this content to:
oldpasswd=password1&newpasswd=password2&confirm=password2&userid=htbadmin&submit=doreset

And we see that password is changed. Then we can sign in and get the answer.

# Session Attacks

## Brute Forcing Cookies

There was a lot of infomration in this section that I didn't feel I needed to copy and paste.

The questions in this section are:
Tamper the session cookie for the application at subdirectory /question1/ to give yourself access as a super user. What is the flag? 

Inspecting the SessionID cookie in burp it is clearly URL encoded. And when un-encoded, it becomes base64, then hex. Decoding fully we get:
user:htbuser;role:student;time:1713734120

Changing that to:
user:htbadmin;role:admin;time:1713734120

and re-encoding:
`echo 'user:htbuser;role:admin;time:1713734120' | xxd -p | base64`
We get NzU3MzY1NzIzYTY4NzQ2MjYxNjQ2ZDY5NmUzYjcyNmY2YzY1M2E2MTY0NmQ2OTZlM2I3NDY5NmQ2NTNhCjMxMzczMTMzMzczMzM0MzEzMjMwMGEK

But this fails to actually work. What I had to was pass the request into Burp with a wordlist of potential roles, then encode as it was originally. I found that the `super` role was the answer.

Log in to the target application and tamper the rememberme token to give yourself super user privileges. After escalating privileges, submit the flag as your answer. 

The hint here is "Correct decoding is the key"

The cookie is: ougfu558t972bpc30usmk58est

This is not base64 or hex.

Forums pointed out to click the remember me box. Now I found the persistent cookie:
HTBPERSISTENT=eJwrLU4tssooSSoF0tZF%2BTmpVsUlpSmpeSXWJZm5qVaG5obG5sYWJqaGAE4TDlE%3D; 

After passed through URL decode it looks like Base64. When I base64 decode the magic bytes look like 78 9C which are related to zlib.

Using Magic, on CyberChef and passing in the base64 encode I get:
user:htbuser;role:student;time:1713738451

Which is the same output as the previous question. But now we can try to the script probably. Or I might be able to just reverse this with super as the role.

Changing the role to super and re-encoding then sending a request with:
Cookie: HTBPERSISTENT=eJwVxlsKACEIAMAziYVhtwmEgmLDx/3dvmbCRHn6eHb9trDF/evrCAMBErZSIQEswQ15; PHPSESSID=kkk6bjvrld0rkharjpkt7ldtt1

Gets the answer.

## Insecure Token Handling

One difference between cookies and tokens is that cookies are used to send and store arbitrary data, while tokens are explicitly used to send authorization data. When we perform token-based authentication such as OpenID, or OpenID Connect, we receive an id token from a trusted authority. This is often referred to as JSON Web Token (JWT) and token-based authentication.

A typical use case for JWT is continuous authentication for Single Sign-On (SSO). However, JWT can be used flexibly for any field where compact, signed, and encrypted information needs to be transmitted. A token should be generated safely but should be handled safely too. Otherwise, all its security could break apart.

A token should expire after the user has been inactive for a given amount of time, for example, after 1 hour, and should expire even if there is activity after a given amount of time, such as 24 hours. If a token never expires, the Session Fixation attack discussed below is even worse, and an attacker could try to brute force a valid session token created in the past. Of course, the chances of succeeding in a brute force attack are proportionate to the shortness of the cookie value itself.

One of the most important rules about a cookie token is that its value should change as soon as the access level changes. This means that a guest user should receive a cookie, and as soon as they authenticate, the token should change. The same should happen if the user gets more grants during a sudo-like session. If this does not occur, the web application, or better any authenticated user, could be vulnerable to Session Fixation.

This attack is carried out by phishing a user with a link that has a fixed, and, unknown by the web application, session value. The web application should bounce the user to the login page because, as discussed, the SESSIONID is not associated with any valid one. When the user logs in, the SESSIONID remains the same, and an attacker can reuse it.

A simple example could be a web application that also sets SESSIONID from a URL parameter like this:

    https://brokenauthentication/view.php?SESSIONID=anyrandomvalue

When a user that does not have a valid session clicks on that link, the web application could set SESSIONID as any random value.

Take the below request as an example.
At line 4 of the server’s response, the Set-Cookie header has the value specified at the URL parameter and a redirect to the login page. If the web application does not change that token after a successful login, the phisher/attacker could reuse it anytime until it expires.

Following the Session Fixation attack, it is worth mentioning another vulnerability named Token in URL. Until recent days, it was possible to catch a valid session token by making the user browse away from a website where they had been authenticated, moving to a website controlled by the attacker. The Referer header carried the full URL of the previous website, including both the domain and parameters and the webserver would log it.

Nowadays, this attack is not always feasible because, by default, modern browsers strip the Referer header. However, it could still be an issue if the web application suffers from a Local File Inclusion vulnerability or the Referer-Policy header is set in an unsafe manner.

If we can read application or web server logs, we may also obtain a high number of valid tokens remotely. It is also possible to obtain valid tokens remotely if we manage to compromise an external analytics or log collection tool used by a web server or application. You can learn more and practice this attack by studying the File Inclusion / Directory Traversal module.

Secure session handling starts from giving the counterpart, the user, as little information as possible. If a cookie contains only a random sequence, an attacker will have a tough time. On the other side, the web application should hold every detail safely and use a cookie value just as an id to fetch the correct session.

Some security libraries offer the feature of transparently encrypting cookie IDs also at the server level. Encryption is performed using some hardcoded values, concatenated to some value taken from the request, such as User-Agent, IP address or a part of it, or another environment variable. An excellent example of this technique has been implemented inside the Snuffleupagus PHP module. Like any other security measure, cookie encryption is not a silver bullet and could cause unexpected issues.

Session security should also cover multiple logins for the same user and concurrent usage of the same session token from different endpoints. A user should be allowed to have access to an account from one device at a time. An exception can be set for mobile access, which should use a parallel session check. Suppose the web application can identify the endpoint, for example, by using the user agent, screen size and resolution, or other tricks used by trackers. In that case, it should set a sticky session on a given endpoint to raise the overall security level.

# Skill Assessment

## Skill Assessment

During our penetration test, we come across yet another web application. While the rest of the team keeps scanning the internal network for vulnerabilities in an attempt to gain an initial foothold, you are tasked with examining this web application for authentication vulnerabilities.

Find the vulnerabilities and submit the final flag using the skills we covered in the module sections to complete this module.

From past penetration tests, we know that the rockyou.txt wordlist has proven effective for cracking passwords.

The only question in this section is:
Assess the web application and use various techniques to escalate to a privileged user and find a flag in the admin panel. Submit the contents of the flag as your answer. 

From the create account page we can determine that the Password must start with a capital letter, must end with a digit, must have at least one of $ # @, and it must be a minimum of 20 characters and cannot be more than 29 characters.

Alongside this, it looks like admin is a "banned" prefix. So I might be able to login just using that information.

Looking the post request for login I see the data looks like:
{
	"userid": "admin",
	"passwd": "test",
	"submit": "submit"
}

So we might be able to fuzz using ffuf.

First lets make a password list using rockyou.txt that only fits the conditions we specified.

`grep "^[A-Z]" rockyou.txt | grep '[[:lower:]]' | grep -e '@' -e '$' -e '#' |  grep -E '^.{20,29}$' | grep "[@\$#]"`

This returns 693 possible passwords. So lets try that on the admin login.

`ffuf -w passwordsShortlist.txt:FUZZ -u 'http://83.136.254.223:52404/login.php' -d 'userid=admin&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

That didn't work, so I tried with the username shortlist:
`ffuf -w passwordsShortlist.txt:FUZZ,/Users/noneya/Useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZNAME -u 'http://83.136.254.223:52404/login.php' -d 'userid=FUZZNAME&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -mc 200 -fs 1807,1825`

Also nothing.

Doesn't seem there is any obvious information being displayed on the password reset link. Just the session ID cookie...

However that cookie is URL encoded and appears to be base64. Lets decode.

084e0343a0486ff05530df6c705c8bb4

Looks like hex... hmm but the result isn't worth much...
NC?Ho?U0?lp\??

Maybe I should use that Magic on CyberChef. It just seems like worthless numbers.

If I try to create an account with test as the user again I get invalid username... maybe I can fuzz for a valid user that way.

The submit data here looks like: 
userid=test&email=test%40email.com&passwd1=Aaaaaaaaaaaaaaaaaaaa%402&passwd2=Aaaaaaaaaaaaaaaaaaaa%402&submit=submit

So lets try:
`ffuf -w /Users/noneya/Useful/SecLists/Usernames/top-usernames-shortlist.txt:FUZZNAME -u 'http://94.237.56.188:37996/register.php' -d 'userid=FUZZNAME&email=test%40email.com&passwd1=Aaaaaaaaaaaaaaaaaaaa%402&passwd2=Aaaaaaaaaaaaaaaaaaaa%402&&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -mc 200`

Interestingly both test and guest return the same size... maybe guest is a user?

Try:
`ffuf -w passwordsShortlist.txt:FUZZ -u 'http://94.237.56.188:37996/login.php' -d 'userid=guest&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

Doesn't seem like it.

When I log I a button that says send a message to another user. And when I try admin it fails saying user not found. Maybe this is where I enumerate.

Resetting the box and logging in again, I pass that request to the send messages again with the same user list.

Hmm guest does exist. So maybe I have wrong list of passwords...

Lets create a new set:
`grep "^[A-Z]" rockyou.txt | grep '[[:lower:]]' |  grep -E '^.{20,29}$'`

Trying again:
`ffuf -w passwordsShortlist.txt:FUZZ -u 'http://83.136.252.32:47603/login.php' -d 'userid=guest&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

Nope...

So reading some hints, they point me to the support page, which says they have unified their accounts into one account support. When I try to send a message to support it works... Maybe I can sign in with that.

`ffuf -w passwordsShortlist.txt:FUZZ -u 'http://83.136.252.32:47603/login.php' -d 'userid=support&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

Nope...

`ffuf -w passwordsShortlist.txt:FUZZ -u 'http://83.136.252.32:47603/login.php' -d 'userid=support.us&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded'`

I'm pretty certain this is the grep I need:
`grep "^[A-Z]" rockyou.txt | grep -E '^.{20,29}$' | grep '[0-9]$' | grep '[[:lower:]]' | grep '[#$@]'`

So I think the issue is that I am not rate limiting. Too many failed attempts make me wait 27 seconds.

Lets try:
`ffuf -w passwordsShortlist.txt:FUZZ -u 'http://94.237.63.83:47837/login.php' -d 'userid=support.us&passwd=FUZZ&submit=submit' -X POST -H 'Content-Type: application/x-www-form-urlencoded' -rate 1`

Still too fast. Lets write a quick python script that waits 30 seconds after 5 attempts before going again.

I wrote the script and got a valid password. One issue I had was the password was being passed in with the newline character. So I had to remove that and I started getting access.

I found a cookie that needs to be tampered with. When I send it threw Magic in CyberChef I get:
b3b8b5cf421d3f96f6469fa618a6bb7f:434990c8a25d2be94863561ae98bd682

When we look at the two sides of the : we can tell this appears to be an md5 hash. So we can try to recreate this cookie the same way. After trying a couple of things we discover the cookie is formatted like:
`support.it:support`

So now we need to write a python function to test other potential roles.
I spent all the effort of writing a python script to test for the role and got the response for the first role I attempted.
admin.us:admin

I tried this manually in Burp and it failed, so I am not sure how it worked in Python. But it did.
