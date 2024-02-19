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

Stored XSS is the most critical form of XSS because it may be difficult to remove, is persistent, and can affect any user that visit the web page.

Its easy to test if a web page is vulnerable to XSS by running this command: `<script>alert(window.origin)</script>`

If the page does not do any input sanatization, this alert will pop as soon as we input the payload, or when we refresh the page.

The reason we use window.origin in the above command is that many modern web apps use cross-domain IFrames to handle user input. This is done so that if the website is vulnerable to XSS, it will only be vulnerable on the web form, not the whole website. This alert box shows the url being executed on in the XSS so we will be able to tell if we are in an IFrame or not.

Some modern web browsers block the use of alert(). Some other options are <plaintext>, which will stop rendering the HTML code that comes after it and display it as plaintext. Another easy-to-spot payload is <script>print()</script> that will pop up the browser print dialog, which is unlikely to be blocked by any browsers. 

The test on this section is:
To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. 

Running `<script>alert(document.cookie)</script>` gets the answer.

## Reflected XSS

Reflected XSS is a form of non-persistent XSS. That means once we add it to the page once it is refreshed it goes away. In every other way it is the same as far as I can tell. But it won't be displayed to other users. Only the person who opens the web page. So the question is how do we use this to our advantage?

The answer depends on the which http request is used to send the input to the server. We can check this through the dev tools under the network tab. For this section, its a get request that is being used. So to target a user, we could send them a url with our payload in it.

Example: `http://94.237.56.248:49399/index.php?task=<script>alert(window.origin)</script>`

This is why it is never recommened to use a url sent to you from someone unless they are completey trusted.

The question for this section is: 
To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. 

Running `<script>alert(document.cookie)</script>` gets the answer.

## DOM XSS

DOM based XSS is different from the other two in that all of the code is executed client side inside the web browser. It is also a non-persistent attack, so this attack would require sharing a url to a user to attack them.

The first thing to notice on DOM based attacks is if the payload is being stored in the DOM or in the server. When we run our payload, if don't see anything in the network tab, and the page is displaying what it should, we can assume it is using the DOM object.

Then we can check how they are modifying the DOM, Javascript commonly uses these three:
`   document.write()
    DOM.innerHTML
    DOM.outerHTML`

And Jquery uses these:
`   add()
    after()
    append()`

If these functions are used without sanatization then this likely vulnerable to a DOM based XSS attack. We can check for sanatization in the script.js file. 

In this section we see that in this example they are not using sanatization and they are using innerHTML. InnerHTML has a restriction on using the <script> tag. But we can use:
`<img src="" onerror=alert(window.origin)>`

This command displays an image, and it allows using code on error. So if we provide it an empty string for the image we can run code to test for DOM based XSS.

The question for this section is:
To get the flag, use the same payload we used above, but change its JavaScript code to show the cookie instead of showing the url. 

Running `<img src="" onerror=alert(document.cookie)>` gets the answer.

## XSS Discovery

Discovery of an XSS can be just as difficult as using the XSS. There are many tools that try to automate the discovery (examples Nessus, Burp Pro, or ZAP). There are also open-source tools such ass XSS Strike, Brute XSS, and XSSer. We can use these by cloning them. They most often test for XSS by identifying input fields on a web page then try a list of payloads and see if they are reflected on the resulting web page.

Another option for discovery is Manual Discovery. For basic XSS vulns, its usually possible to find by just testing input variables. But for advance XSS vulns, we need to use advanced code review skills.

If we want to test using the basic method, we can use the payloads found here: `https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/XSS%20Injection/README.md` or here `https://github.com/payloadbox/xss-payload-list`

The most efficent way of doing this would be to write a python script that automates testing these payloads so we can have a test specific to the web app. But this is outside of the scope of the module.

The most effective way to find XSS is manual code review. If we know exactly how the input is being processed, we can design an attack that has a high probability of working. 

For common web apps, we are unlikely to find XSS through XSS tools or payloads. This is because most people will run their app through these tools and then patch the vulns before release. Thus advanced code review is more likely to find these issues.

The questions for this section are:
Utilize some of the techniques mentioned in this section to identify the vulnerable input parameter found in the above server. What is the name of the vulnerable parameter? 

Running the site through Zaps passive and active scans did not discover anything. So I cloned XSStrike and ran `python3 xsstrike.py -u 'http://83.136.249.57:56419/?fullname=test&username=test&password=test&email=test%40email.com'` 

This returned that the vulnerable parameter is email, and it is a reflected vuln.

# XSS Attacks

## Defacing

## Phishing

## Session Hijacking

# XSS Prevention

## XSS Prevention

# Skills Assessment

## Skills Assessment
