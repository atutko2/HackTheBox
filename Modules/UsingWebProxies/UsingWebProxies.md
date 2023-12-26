# Web Proxy

## Proxy Setup

Both ZAP and Burpe Suite have built in browsers to use for Web Proxies. This automatically routes the web traffic through the tool. Burp: Proxy>Intercept>Open Browser Zap: Click Firefox Browser
Needed to install Certs for Burp Suite and Zap so that I can use Proxies. I then had to add them to firefox under preferences>privacy>view Certificates>Authorities>Import

## Intercepting Web Requests

This section covers how to intercept and begin manipulating web requests. Specifically it shows a command injection via HTTP request. If the http request is not verified in the backend it is possible to bypass the security and inject commands. The example here was intercepting a request to an IP address, then changing the ip field on the request to run ls, to list the contents of the directory. The solution to this challenge was to pass in the command `ip=;cat flag.txt;`

## Interception Responses

## Automatic Modification

## Repeating Requests

## Encoding/Decoding

## Proxying Tools

# Web Fuzzer

## Burp Intruder

## ZAP Fuzzer

# Web Scanner

## Burp Scanner

## ZAP Scanner

## Extensions

# Skills Assessment

## Skills Assessment - Using Web Proxies
