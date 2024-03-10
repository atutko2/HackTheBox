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

# Bypassing Filters

## Client-Side Validation

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
