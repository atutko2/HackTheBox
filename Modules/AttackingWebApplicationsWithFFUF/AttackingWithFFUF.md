# Introduction

## Introduction

This section just covers that we will be using FFUF (Fuzz Faster You Fool)

## Web Fuzzing

This section gives an overview of what Fuzzing is and what Web Fuzzing is. They give the example that if we were fuzzing a sql injection attack we would provide a list of random characters to see if it will allow for injection. Similarly if we were fuzzing a buffer overflow, we would be providing gradually increasing strings. 

For web fuzzing, we are often fuzzing to find hidden or forgotten pages. So we might be fuzzing the URL with a list of frequently used page names. For this module it seems we will be using the SecLists directory-list-2.3-small.txt.

This can be found at `SecLists/Discovery/Web-Content/directory-list-2.3-small.txt`

# Basic Fuzzing

## Page Fuzzing

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

In the previous section we found a blog directory, but it was blank. In this section we fuzz to find if there are any actual pages in this directory. The first thing we need to do is determine which file extension the server is using. We could try and guess based on the type of server (e.g Apache maybe .php, IIS might be .asp or .aspx, etc). However, this is clunky. 

We can actually try and fuzz the answer here by looking for a index.(extension) file. If we run `ffuf -w SecLists/Discovery/Web-Content/web-extensions.txt:FUZZ -u http://IP:port/blog/indexFUZZ` we find that the index page has a .php extension.

Now that we know the extension we can start fuzzing for other pages using the same list we used in the previous section.
`ffuf -w SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://IP:Port/blog/FUZZ.php`

This returns two pages, one is just the index page again, which is empty, but the other is the home page.
Running `curl http://IP:port/blog/home.php` finds the flag.

## Recursive Fuzzing

This section covers that we can recursively run the commands we have already run to find all of the subdomains. By adding the -recursion flag to ffuf and the -recursion-depth flag to set how far to check we can check if there is any more that we missed. We can also add the -e flag to define the extension we are looking for, this will double the size of our search list because it will check the word, then check again with the extension. Finally we use -v to get the full url of the found page. And I also added -ic to remove the copyright info from our wordlist.

Running `ffuf -w ../SecLists/Discovery/Web-Content/directory-list-2.3-small.txt:FUZZ -u http://94.237.53.58:55018/FUZZ -recursion -recursion-depth 1 -e .php -v -ic` we find a page under /forum/flag.php.

Running curl on the URL gets the flag.

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
