# Intro

## Intro to Command Injections

Command injection is when user input is taken and not sanatized, then used as part of a command on the server. This allows for a potentially breaking out of the confines of that command and running un-expected and potentially harmful commands on the server.

There are lots of examples of command injection, SQL Injection, Code Injection, OS Command Injection, etc. This is currently number 3 on OWASP top 10 Web App Risks.

# Exploitations

## Detection

To detect command injection, we would do the same thing we would do if we were planning to exploit command injection. We simply attempt to append a command using various injection methods. If the output is something other than normal, then we succesfully exploited the command injection vulnerability. For more advancecd injections we might use Fuzzing to do this. Or use code review. But in general that is the process.

For command injection there are a few characters that help us:

Injection Operator  |	Injection Character |	URL-Encoded Character |	Executed Command                           |
-----------------   |   ------------------  |   --------------------- | ----------------                           |
Semicolon 	    |	; 		    |	%3b 		      |	Both                                       |
New Line 	    |	\n 		    |	%0a 		      |	Both                                       |
Background 	    |	& 		    |	%26 		      |	Both (second output generally shown first) |
Pipe 		    |	| 		    |	%7c 		      |	Both (only second output is shown)         |
AND 		    |	&& 		    |	%26%26 		      |	Both (only if first succeeds)              |
OR 		    |	|| 		    |	%7c%7c 		      |	Second (only if first fails)               |
Sub-Shell 	    |	`` 		    |	%60%60 		      |	Both (Linux-only)                          |
Sub-Shell 	    |	$() 		    |	%24%28%29 	      |	Both (Linux-only)                          |


## Injecting Commands

This webapp doesn't allow for direct injection of a command, but if you look at the network in the dev tools, you notice there are no web requests made. So it is very possible this command validation is all happening on the front end. Front end validation is very easily bypassable by sending web requests directly from something like Zap or Burp.

All we have to do is start the request interceptor on one of these, and try to send the request, then modifying the post to include our command. The response should contain the output of the other command if it is vulnerable.

The question in this section is:
Review the HTML source code of the page to find where the front-end input validation is happening. On which line number is it? 

Once you open the source code you see that on input field there is a patter expected.

## Other Injection Operators

We can use the other injection operators listed in the table above to do the same thing. The main take away of these are that || and | are maybe the best for clean output because they don't require the original output to come out. But they rely on the first command failing. So we would need to send a failing command || our new command. Like `ping -c 1 || whoami`

The question in this section is:
Try using the remaining three injection operators (new-line, &, |), and see how each works and how the output differs. Which of them only shows the output of the injected command? 

The answer is |

# Filter Evasion

## Identifying Filters

Some web applications use a blacklist of characters that cannot be used (though realistically it would likely be a whitelist). If a character or command is blacklisted, it could indicate a WAF or just backend validation.

We can test where the blacklist happens by going character by character until we get the fail message. It appears the ; is blacklisted. 

The question in this section is:
Try all other injection operators to see if any of them is not blacklisted. Which of (new-line, &, |) is not blacklisted by the web application? 

I literally got a bunch of these to work? Apparently the answer was new-line written like that. But the or operator definitly worked too. This was frustrating because it gave no hint as to how they wanted the input so I kept doing \n or its encoded form. 

## Bypassing Space Filters

Space is a commonly blacklisted character. Especially when we know the input should not have it. However, the newline character is frequently not blacklisted as the payload itself might need it.

To bypass the space filter, we can attempt to use tabs instead `%09` tabs and spsaces are treated the same in linux and windows. So commands will still run.

We can also try to use ${IFS} which defaults to a space and a tab in Linux.
Like: `127.0.0.1%0a${IFS}`

Or we can try Bash Brace Expansion which automatically adds spaces between arguments. 
Like: `127.0.0.1%0a{ls,-la}`

We can visit PayloadAllTheThings `https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection#bypass-without-space` for other potential options.

The question in this section is:
Use what you learned in this section to execute the command 'ls -la'. What is the size of the 'index.php' file?

Running `ip=127.0.0.1%0a%09ls%09-la` gets the answer.

## Bypassing Other Blacklisted Characters

Most of the time the / and \ characters are going to be part of the blacklist because they are used in directory traversal. However, we can use environment variables to achieve the same result. 

For instance we can use ${PATH} to get all the path variables on a linue box. Then we can do something like ${PATH:0:1} to get just the first character on the path. Which is likely /

We can do the same thing with $HOME or $PWD.

For the semicolon, we could use something like ${LS_COLORS:10:1} to get that.

We can use `printenv` to see all the environment variables and see what we can use to our advantage.

On windows command line we can use something like `%HOMEPATH:~6,-11%` to get the \ character

And in powershell since environment variables are arrays all we have to do is 
``` Powershell
$env:HOMEPATH[0]
``` 
to get a character

## Bypassing Blacklisted Commands

## Advanced Command Obfuscation

## Evasion tools

# Prevention

## Command Injection Prevention

# Skills Assessment

## Skills Assessment
