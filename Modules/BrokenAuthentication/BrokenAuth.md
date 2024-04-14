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

## Predictable Reset Token

# Password Attacks

## Authentication Credentials Handling

## Guessable Answers

## Username Injection

# Session Attacks

## Brute Forcing Cookies

## Insecure Token Handling

# Skill Assessment

## Skill Assessment


