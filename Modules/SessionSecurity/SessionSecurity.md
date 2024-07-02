# Intro

## Intro

A user session can be defined as a sequence of requests originating from the same client and the associated responses during a specific time period. Modern web applications need to maintain user sessions to keep track of information and status about each user. User sessions facilitate the assignment of access or authorization rights, localization settings, etc., while users interact with an application, pre, and post-authentication.

HTTP is a stateless communication protocol, and as such, any request-response transaction is unrelated to other transactions. This means that each request should carry all needed information for the server to act upon it appropriately, and the session state resides on the client's side only.

For the reason above, web applications utilize cookies, URL parameters, URL arguments (on GET requests), body arguments (on POST requests), and other proprietary solutions for session tracking and management purposes.

A unique session identifier (Session ID) or token is the basis upon which user sessions are generated and distinguished.

We should clarify that if an attacker obtains a session identifier, this can result in session hijacking, where the attacker can essentially impersonate the victim in the web application.

An attacker can obtain a session identifier through a multitude of techniques, not all of which include actively attacking the victim. A session identifier can also be:

    Captured through passive traffic/packet sniffing
    Identified in logs
    Predicted
    Brute Forced

Now let us focus on session identifier security for a minute.

A session identifier's security level depends on its:

    Validity Scope (a secure session identifier should be valid for one session only)
    Randomness (a secure session identifier should be generated through a robust random number/string generation algorithm so that it cannot be predicted)
    Validity Time (a secure session identifier should expire after a certain amount of time)

The established programming technologies (PHP, JSP, etc.) generate session identifiers that "comply" with the above validity scope, randomness, and validity time requirements. If you come across a custom session identifier generation implementation, proceed with extreme caution and be as exhaustive as possible in your tests.

A session identifier's security level also depends on the location where it is stored:

    URL: If this is the case, the HTTP Referer header can leak a session identifier to other websites. In addition, browser history will also contain any session identifier stored in the URL.
    HTML: If this is the case, the session identifier can be identified in both the browser's cache memory and any intermediate proxies
    sessionStorage: SessionStorage is a browser storage feature introduced in HTML5. Session identifiers stored in sessionStorage can be retrieved as long as the tab or the browser is open. In other words, sessionStorage data gets cleared when the page session ends. Note that a page session survives over page reloads and restores.
    localStorage: LocalStorage is a browser storage feature introduced in HTML5. Session identifiers stored in localStorage can be retrieved as long as localStorage does not get deleted by the user. This is because data stored within localStorage will not be deleted when the browser process is terminated, with the exception of "private browsing" or "incognito" sessions where data stored within localStorage are deleted by the time the last tab is closed.


Session identifiers that are managed with no server interference or that do not follow the secure "characteristics" above should be reported as weak.



    Session Hijacking: In session hijacking attacks, the attacker takes advantage of insecure session identifiers, finds a way to obtain them, and uses them to authenticate to the server and impersonate the victim.

    Session Fixation: Session Fixation occurs when an attacker can fixate a (valid) session identifier. As you can imagine, the attacker will then have to trick the victim into logging into the application using the aforementioned session identifier. If the victim does so, the attacker can proceed to a Session Hijacking attack (since the session identifier is already known).

    XSS (Cross-Site Scripting) <-- With a focus on user sessions

    CSRF (Cross-Site Request Forgery): Cross-Site Request Forgery (CSRF or XSRF) is an attack that forces an end-user to execute inadvertent actions on a web application in which they are currently authenticated. This attack is usually mounted with the help of attacker-crafted web pages that the victim must visit or interact with. These web pages contain malicious requests that essentially inherit the identity and privileges of the victim to perform an undesired function on the victim's behalf.

    Open Redirects <-- With a focus on user sessions: An Open Redirect vulnerability occurs when an attacker can redirect a victim to an attacker-controlled site by abusing a legitimate application's redirection functionality. In such cases, all the attacker has to do is specify a website under their control in a redirection URL of a legitimate website and pass this URL to the victim. As you can imagine, this is possible when the legitimate application's redirection functionality does not perform any kind of validation regarding the websites which the redirection points to.


We will refer to URLs such as http://xss.htb.net throughout the module sections and exercises. We utilize virtual hosts (vhosts) to house the web applications to simulate a large, realistic environment with multiple webservers. Since these vhosts all map to a different directory on the same host, we have to make manual entries in our /etc/hosts file on the Pwnbox or local attack VM to interact with the lab. This needs to be done for any examples that show scans or screenshots using an FQDN.

To do this quickly, we could run the following (be reminded that the password for your user can be found inside the my_credentials.txt file, which is placed on the Pwnbox's Desktop):

```
IP=ENTER SPAWNED TARGET IP HERE
printf "%s\t%s\n\n" "$IP" "xss.htb.net csrf.htb.net oredirect.htb.net minilab.htb.net" | sudo tee -a /etc/hosts
```

You may wish to write your own script or edit the hosts file by hand, which is fine.

If you spawn a target during a section and cannot access it directly via the IP be sure to check your hosts file and update any entries!

Module exercises that require vhosts will display a list that you can use to edit your hosts file after spawning the target VM at the bottom of the respective section.

Let's now dive into each of the previously mentioned session attacks and vulnerabilities in detail.

# Session Attacks

## Session Hijacking

In session hijacking attacks, the attacker takes advantage of insecure session identifiers, finds a way to obtain them, and uses them to authenticate to the server and impersonate the victim.

An attacker can obtain a victim's session identifier using several methods, with the most common being:

    Passive Traffic Sniffing
    Cross-Site Scripting (XSS)
    Browser history or log-diving
    Read access to a database containing session information

As mentioned in the previous section, if a session identifier's security level is low, an attacker may also be able to brute force it or even predict it.

Navigate to http://xss.htb.net and log in to the application using the credentials below:

    Email: heavycat106
    Password: rocknrol

This is an account that we created to look into the application!

You should now be logged in as "Julie Rogers."

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that the application is using a cookie named auth-session most probably as a session identifier. Double click this cookie's value and copy it! 

Now, suppose that you are the attacker and you somehow got access to the auth-session cookie's value for the user "Julie Rogers".

Open a New Private Window and navigate to http://xss.htb.net again. Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), replace the current auth-session cookie's value with the one you copied in Part 1. Reload the current page, and you will notice that you are logged in as "Julie Rogers" without using any credentials!


-----------
The question in this section is:
What kind of session identifier does the application employ? Answer options (without quotation marks): "URL parameter", "URL argument", "body argument", "cookie" or "proprietary solution" 

The answer is cookie

## Session Fixation

Session Fixation occurs when an attacker can fixate a (valid) session identifier. As you can imagine, the attacker will then have to trick the victim into logging into the application using the aforementioned session identifier. If the victim does so, the attacker can proceed to a Session Hijacking attack (since the session identifier is already known).

Such bugs usually occur when session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data (more on that in a bit).

Session Fixation attacks are usually mounted in three stages:



Stage 1: Attacker manages to obtain a valid session identifier

Authenticating to an application is not always a requirement to get a valid session identifier, and a large number of applications assign valid session identifiers to anyone who browses them. This also means that an attacker can be assigned a valid session identifier without having to authenticate.

Note: An attacker can also obtain a valid session identifier by creating an account on the targeted application (if this is a possibility).

Stage 2: Attacker manages to fixate a valid session identifier

The above is expected behavior, but it can turn into a session fixation vulnerability if:

    The assigned session identifier pre-login remains the same post-login and
    Session identifiers (such as cookies) are being accepted from URL Query Strings or Post Data and propagated to the application

If, for example, a session-related parameter is included in the URL (and not on the cookie header) and any specified value eventually becomes a session identifier, then the attacker can fixate a session.

Stage 3: Attacker tricks the victim into establishing a session using the abovementioned session identifier

All the attacker has to do is craft a URL and lure the victim into visiting it. If the victim does so, the web application will then assign this session identifier to the victim.

The attacker can then proceed to a session hijacking attack since the session identifier is already known.

Proceed to the end of this section and click on Click here to spawn the target system! or the Reset Target icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target application and follow along. Don't forget to configure the specified vhost (oredirect.htb.net) to access the application.

Part 1: Session fixation identification

Navigate to oredirect.htb.net. You will come across a URL of the below format:

http://oredirect.htb.net/?redirect_uri=/complete.html&token=<RANDOM TOKEN VALUE>

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that the application uses a session cookie named PHPSESSID and that the cookie's value is the same as the token parameter's value on the URL.

If any value or a valid session identifier specified in the token parameter on the URL is propagated to the PHPSESSID cookie's value, we are probably dealing with a session fixation vulnerability.

Let us see if that is the case, as follows.

Part 2: Session fixation exploitation attempt

Open a New Private Window and navigate to http://oredirect.htb.net/?redirect_uri=/complete.html&token=IControlThisCookie

Using Web Developer Tools (Shift+Ctrl+I in the case of Firefox), notice that the PHPSESSID cookie's value is IControlThisCookie

We are dealing with a Session Fixation vulnerability. An attacker could send a URL similar to the above to a victim. If the victim logs into the application, the attacker could easily hijack their session since the session identifier is already known (the attacker fixated it).

Note: Another way of identifying this is via blindly putting the session identifier name and value in the URL and then refreshing.

For example, suppose we are looking into http://insecure.exampleapp.com/login for session fixation bugs, and the session identifier being used is a cookie named PHPSESSID. To test for session fixation, we could try the following http://insecure.exampleapp.com/login?PHPSESSID=AttackerSpecifiedCookieValue and see if the specified cookie value is propagated to the application (as we did in this section's lab exercise).

Below is the vulnerable code of this section's lab exercise.

``` php
<?php
    if (!isset($_GET["token"])) {
        session_start();
        header("Location: /?redirect_uri=/complete.html&token=" . session_id());
    } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
?>
```

Let us break the above piece of code down.
``` php
if (!isset($_GET["token"])) {
     session_start();
```

The above piece of code can be translated as follows: If the token parameter hasn't been defined, start a session (generate and provide a valid session identifier).

``` php
header("Location: /?redirect_uri=/complete.html&token=" . session_id());
```

The above piece of code can be translated as follows: Redirect the user to /?redirect_uri=/complete.html&token= and then call the session_id() function to append session_id onto the token value.

``` php
 } else {
        setcookie("PHPSESSID", $_GET["token"]);
    }
```
The above piece of code can be translated as follows: If the token parameter is already set (else statement), set PHPSESSID to the value of the token parameter. Any URL in the following format http://oredirect.htb.net/?redirect_uri=/complete.html&token=AttackerSpecifiedCookieValue will update PHPSESSID's value with the token parameter's value.

By now, we have covered session hijacking and session fixation. Moving forward, let us see some ways through which a bug bounty hunter or penetration tester can obtain valid session identifiers that can be then used to hijack a user's session.

-----------
The question in this section is:
 If the HttpOnly flag was set, would the application still be vulnerable to session fixation? Answer Format: Yes or No 

Yes

## Obtaining Session Identifiers without User Interaction



## Cross Site Scripting XSS

## Cross Site Request Forgery

## Cross-Site Request Forgery (Get-based)

## Cross-Site Request Forgery (Post-based)

## CSS & CSRF Chaining

## Exploiting Weak CSRF Tokens

## Additional CSRF Protection Bypasses

## Open Redirect

## Remediation Advice

# Skills Assessment

## Skills Assessment


