import requests
import json
import urllib.parse

BASE_URL = "https://web.cryptohack.org" 
#the hashfunc was supposed to be SHA256, but the server return raw message instead.
#the raw message could be long compared to the SHA256 output,
#so generally, the server will truncated just the first bytes
#therefore, hashfunc(a)=hashfunc(b) when a and b shares a long enough common prefix
#so the signature of {"admin": false, "username": "bob"} 
# can be used to sign any message that starts with the same prefix
#  e.g. {"admin": false, "username": "bob", "admin": true}
# noteably, the json above evaluates to {"admin": true, "username": "bob"} 
#thats the idea of the attack

# The server will generate: {"admin": false, "username": "bob"}
sign_res = requests.get(f"{BASE_URL}/digestive/sign/bob/").json()
valid_signature = sign_res["signature"]
malicious_msg = '{"admin": false, "username": "bob", "admin": true}'
encoded_msg = urllib.parse.quote(malicious_msg)
verify_url = f"{BASE_URL}/digestive/verify/{encoded_msg}/{valid_signature}/"
verify_res = requests.get(verify_url).json()
print(verify_res)  

