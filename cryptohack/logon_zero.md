# Logon Zero
## Description
>Before using the network, you must authenticate to Active Directory using our timeworn CFB-8 logon protocol.
Connect at socket.cryptohack.org 13399

## My solution
After reading the `decrypt()` function in the challenge file carefully, I found out that all character in the plaintext returned by the function all satisfies:\
$p[i] = (E_k(c[i:i+16]))[0]$ $\bigoplus c[i+16] $ 

So if we send `c` that repeats the same bytes multiple times, the resulting `p` will also be a series repeating one random bytes. Note that the `password_length` is assigned to the last bytes of `p`, so our goal
here is to make `p`=`x\00`*`len(p)` in order to make `password`= "". I repeatly did the following steps:
* `reset_connection` for different key each time
* `reset_password` with `token`=`"00"*32`
* `authenticate` with `password` = ""
```

while(True):
    to_send={"option":"reset_connection"}
    json_send(to_send)
    response_reset = json_recv()
    payload=long_to_bytes(0).hex()
    payload=str(payload)*32
    print(payload)

    to_send={"option":"reset_password","token": payload}
    json_send(to_send)
    response_reset = json_recv()
    print(response_reset)

    to_send={"option":"authenticate","password":""}
    json_send(to_send)
    aha=json_recv()
    print(aha)

    if("Welcome" in aha["msg"]):
      break
```
```
0000000000000000000000000000000000000000000000000000000000000000
{'msg': 'Password has been correctly reset.'}
{'msg': 'Wrong password.'}
0000000000000000000000000000000000000000000000000000000000000000
{'msg': 'Password has been correctly reset.'}
{'msg': 'Wrong password.'}
0000000000000000000000000000000000000000000000000000000000000000
{'msg': 'Password has been correctly reset.'}
{'msg': 'Wrong password.'}
0000000000000000000000000000000000000000000000000000000000000000
{'msg': 'Password has been correctly reset.'}
{'msg': 'Wrong password.'}
```
It may take a while to finally see the flag
```
0000000000000000000000000000000000000000000000000000000000000000
{'msg': 'Password has been correctly reset.'}
{'msg': 'Welcome admin, flag: crypto{Zerologon_Windows_CVE-2020-1472}'}
```
