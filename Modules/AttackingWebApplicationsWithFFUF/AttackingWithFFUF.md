# Introduction

## Introduction

This section just covers that we will be using FFUF (Fuzz Faster You Fool)

## Web Fuzzing

This section gives an overview of what Fuzzing is and what Web Fuzzing is. They give the example that if we were fuzzing a sql injection attack we would provide a list of random characters to see if it will allow for injection. Similarly if we were fuzzing a buffer overflow, we would be providing gradually increasing strings. 

For web fuzzing, we are often fuzzing to find hidden or forgotten pages. So we might be fuzzing the URL with a list of frequently used page names. For this module it seems we will be using the SecLists directory-list-2.3-small.txt.

This can be found at `SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`

# Basic Fuzzing

This goes over a quick fuzzing example to find directories. It covers some of the parameters you can use with ffuf. The big ones are:
-w is the wordlist
-u is the url 

But there are ways to do filtering. 
-fc filters on response code
-fs filters on response size (i.e. if you know its not a specific size remove it)

There are also matcher options and output options

Use ffuf -h to find all options

We also run a fuzz on the provided instance. There is a question in this section:

In addition to the directory we found above, there is another directory that can be found. What is it? 
Running `ffuf -w ../../SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://83.136.252.214:52071/FUZZ` returns 2 directories. The answer to this was forum.

## Directory Fuzzing

## Page Fuzzing

## Recursive Fuzzing

# Domain Fuzzing

## DNS Records

## Sub-domain Fuzzing

## Vhost Fuzzing

## Filtering Results

# Parameter Fuzzing

## Parameter Fuzzing - GET

## Parameter Fuzzing - POST

## Value Fuzzing

# Skills Assessment

## Skills Assessment - Web Fuzzing
