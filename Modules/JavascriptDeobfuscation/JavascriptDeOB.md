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

## HTTP Requests

## Decoding

# Skills Assessment

## Skills Assessment

## Summary
