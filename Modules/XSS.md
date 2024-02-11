# XSS Basics

## Intro to XSS

### What is XSS

XSS is an attack where a website does not perform sufficent input sanatization and a malicious attacker inputs code in an input field like a comment/reply system. Then when other users open that page they unknowingly execute that malicious code.

XSS Vulns. are solely on the client-side and do not directly affect the back-end server. They can only affect the user executing the vuln. However, since it is so prevalent, this is counted a medium risk vuln.

### XSS Attacks

XSS attacks can do a lot of things. Common examples would be having the user write their session cookie to the attackers server, or perhaps changing the users password to something the hacker wants. There are many of these types of attacks.

As XSS attacks execute JavaScript code within the browser, they are limited to the browser's JS engeine. They cannot run system wide. In modern browsers they are also limited to running on the same domain as the vulnerable website.

XSS Vulns have been found in almost all modern web apps. A famous one is the Samy Worm that affected MySpace in 2005. Another was found in 2014 on Twitter that caused Twitter to shit down the TweetDeck until it was fixed. This has even affected Google.

### Types of XSS

There are three main types of XSS:

Stored (Persistent) XSS - This is the most critical type. In this form the user input is stored on the back-end database and then displayed upon retrieval (thing comments/posts)

Reflected (Non-Persistent) XSS - Occurs when user input is displayed on the page after being processed by the backend server, but without being stored (Search result or error message)

DOM-Bassed XSS - Non-Persistent XSS type that occurs when user input is directly shown in the browser and is completely processed on the client-side, without reaching the back-end server (e.g., through client-side HTTP parameters or anchor tags)

## Stored XSS



## Reflected XSS

## DOM XSS

## XSS Discovery

# XSS Attacks

## Defacing

## Phishing

## Session Hijacking

# XSS Prevention

## XSS Prevention

# Skills Assessment

## Skills Assessment
