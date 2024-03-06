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

## Other Injection Operators

# Filter Evasion

## Identifying Filters

## Bypassing Space Filters

## Bypassing Other Blacklister Characters

## Bypassing Blacklisted Commands

## Advanced Command Obfuscation

## Evasion tools

# Prevention

## Command Injection Prevention

# Skills Assessment

## Skills Assessment
