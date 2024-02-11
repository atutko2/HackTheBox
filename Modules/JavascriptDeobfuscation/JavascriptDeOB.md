# Introduction

## Introduction

This module covers what code obfuscation is, how to detect it, and how to de-obfuscate it.

## Source Code

This just covers opening the source cover of a web page. You can access the javascript easily by clicking the scipt file link. And the same is true of the CSS.

The question in this section is:
### Repeat what you learned in this section, and you should find a secret flag, what is it? 

The answer is `HTB{4lw4y5_r34d_7h3_50urc3}` which is found in a comment of the source code.

# Obfuscation

## Code Obfuscation

Code obfuscation is a way to make code less readable. This is often done with other code that aautomatically generates the newly obfuscated code. Obfuscated code does the same thing as the original, but its goal is to make it hard for people/computers tell what it is doing.

There are many reasons to do this, for instance since Javascript is run on the client-side, in a web app, a person might use obfuscation to help prevent an attacker from identifying vulnerabilities in the source code. Or it could be done to help prevent a developers code to be copied or reverse engineered. But usually this is done by attackers to prevent Intrusion Detection and Prevention systems from detecting their scripts.

## Basic Obfuscation

This section covers two forms of basic obfuscation, minifying and packing.

Minifying code is just the act of putting all the code on one line of code. This is possible in many languages and is not exclusive to javascript. But in javascript, a file that has had this done is usually saved in a .min.js file.

Packing is a little better at obfuscation. What it does is it attempts to convert all words and symbols of the code into a list or dictionary and then refer to them using the (p,a,c,k,e,d) function to rebuild the code.

Both of these obfuscators have the problem of keeping the codes main string in clear text though.

## Advanced Obfuscation

Now we are looking at obfuscators that actually remove all clear text.

One such example is base64 encoding using `https://obfuscator.io`. This will completely convert the code into something that is not human readable. This can be done multiple times if desired and it still will work.

We can also use `http://www.jsfuck.com/` to mess up code. This makes it even harder to read. However, this will slow the code down slowly. So this indicates doing this can cause code performance issues.

## Deobfuscation

This section covers some tools for deobfuscation. But these tools only really work on the basic obfuscators such as packing and minifying. This section notes that as the obfuscation becomes more advanced automated tools become much more difficult to make. And if the original obfuscator is custom made then a deobfuscator would also have to be custom made.

The question in this section is:
### Using what you learned in this section, try to deobfuscate 'secret.js' in order to get the content of the flag. What is the flag? 

The answer is `HTB{1_4m_7h3_53r14l_g3n3r470r!}` which was gotten by taking the code in secret.js and running it through `https://matthewfl.com/unPacker.html`

# Deobfuscation Examples

## Code Analysis

If we analyze the unpacked code from above we see that the code is making a web request to /serial.php. It is making a POST request to a function called generateSerial. But it isn't using a return value or anything, and there is no button to use this on the web page. This may indicate unfinished or forgotten functionality. This often has errors or vulnerabilities.

## HTTP Requests

This section covers how to use curl to make web requests like the one mentioned in the above section. 

If we want to use curl to make a POST request all we have to do is add the -X POST flag.
POST requests usually have data to send too, so we add the -d flag and add the data.
`curl -s http://SERVER_IP:PORT/ -X POST -d "param1=sample"`

There are ways to do GET requests with curl too.

The question of this section is:
### Try applying what you learned in this section by sending a 'POST' request to '/serial.php'. What is the response you get? 

Running `curl -s -X POST http://94.237.56.188:37837/serial.php` gets the answer which is N2gxNV8xNV9hX3MzY3IzN19tMzU1NGcz

## Decoding

Another aspect of obfuscation is encodings. Often times return values might be encoded to make for harder reading. There are many types of encodings such as base64, hex, rot13, etc.

To identify base64 encoding is pretty easy. The result of base64 encoding will always be alphanumeric in nature, and has to be a multiple of 4. If the result of the encoding is not a multiple of 4, then encoder = as padding.

You can encode into base64 in linux very easily by running `echo [ThingToEncode] | base64`

Similarly decoding is just as easy by running `echo [ThingToEncode] | base64 -d`

Spotting Hex encoding is just as easy because the resulting encoding has to be with a 16 character set. Hex is coded with 0-9 and a-f. So if the encoding only has those characters chances are its hex.

To encode into hex we can use xxd -p like `echo [ThingToEncode] | xxd -p`

To decode we can use xxd -p -r like `echo [ThingToEncode] | xxd -p -r`

Finally rot13 is just a form of Caesar encoding in which each letter is shifted by some fixed number. It covers how to use tr to create rot13 encoder and decoder here, but I don't think it was worth putting it down.

It does also mention that there is a tool called Cipher Indentifier here `https://www.boxentriq.com/code-breaking/cipher-identifier` that usually correctly identifies the form of encoding. Then decoding should be easier. However, this is not fool proof and some people use encryption to perform their encoding which code make it nearly impossible to decode.

The question in this section is:
### Using what you learned in this section, determine the type of encoding used in the string you got at previous exercise, and decode it. To get the flag, you can send a 'POST' request to 'serial.php', and set the data as "serial=YOUR_DECODED_OUTPUT". 

Analyzing the return value from the previous section I only see alphanumeric results, so it appears to be base64. Running it through a decoder I get: '7h15_15_a_s3cr37_m3554g3'

Sending a curl post request with that using `curl -s -X POST http://94.237.56.188:37837/serial.php -d 'serial=7h15_15_a_s3cr37_m3554g3'` gets the answer 'HTB{ju57_4n07h3r_r4nd0m_53r14l}'

# Skills Assessment

## Skills Assessment

The questions in this section are:

### Try to study the HTML code of the webpage, and identify used JavaScript code within it. What is the name of the JavaScript file being used? 

Looking at the source code its quickly seen that the script file is named 'api.min.js'. From what we learned from before we can quickly guess this file has been minified.

### Once you find the JavaScript code, try to run it to see if it does any interesting functions. Did you get something in return? 

Running the code in that file we see this `HTB{j4v45cr1p7_3num3r4710n_15_k3y}`

### As you may have noticed, the JavaScript code is obfuscated. Try applying the skills you learned in this module to deobfuscate the code, and retrieve the 'flag' variable. 

Based on the (p,a,c,k,e,d) we can tell this has been run through a packer. Running through a depacker we find: `HTB{n3v3r_run_0bfu5c473d_c0d3!}`

### Try to Analyze the deobfuscated JavaScript code, and understand its main functionality. Once you do, try to replicate what it's doing to get a secret key. What is the key? 

Analyzing the script we see another http POST request to /keys.php. Running a curl post request to that address gets: 4150495f70336e5f37333537316e365f31355f66756e

The answer to this question is '4150495f70336e5f37333537316e365f31355f66756e'. However analyzing that encoding we can go further.

Looking at this encoding I see numbers from 0-9 and letters a-f so this is likely a hex encoding. Running `echo 4150495f70336e5f37333537316e365f31355f66756e | xxd -p -r`

The answer is `API_p3n_73571n6_15_fun`

### Once you have the secret key, try to decide it's encoding method, and decode it. Then send a 'POST' request to the same previous page with the decoded key as "key=DECODED_KEY". What is the flag you got?

Since we already decoded this above. We can now run `curl http://83.136.251.235:35263/keys.php -X POST -d 'key=API_p3n_73571n6_15_fun'` and get the answer.

The answer is HTB{r34dy_70_h4ck_my_w4y_1n_2_HTB}

## Summary

This section just covers what we covered in the module.
