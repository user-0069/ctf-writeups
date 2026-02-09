## Description
[chall.py](https://training.bksec.vn/apiv2/files/local/cBAJW8u-Sw2sQ2bmcXzR5?iat=1770632400&sig=rdc_0Yl4aJ2bc4iLiKqixHrzNC05UkNTNVmHkyykFNg)\
[output.txt](https://training.bksec.vn/apiv2/files/local/vyyMWcDGzhQ2QOL2W-3sO?iat=1770632400&sig=1iX2JoRFi04lLIrFsUQCWo5jt9GoMLY9OwtXO9PEtOg)
## My Solution
All the thing we need is right in the output: the key and iv+ciphertext. We just use that to decrypt by AES CFB mode.
```
enc_flag = '6b5113d4b7fcd79b9a909c0a82196a21205ce45df91d241807cfa71b2bf0f76aca25acd632026ccd0642814905883bddec6bad0246181e11833805d628353a17b9462243973d8f189a7e8723423928ac0074277edd8a2d'
enc1 = '2852f8f287f95afcd6cb87e07ebade7d8feff91ba9713521943d42692ccd929d32c64c45b8dcb2accdedb00fcba7d3a66c90'
enc2 = '642c1a66c83913abbdb80cb4283acb3c573d5568d8d744ec7a80caf18608c70f'
key=b'\xd7v\x95Aa!\xc3f\xb9\xc9\x89\xc7z\xc2\xdb\xd6'
enc_flag = bytes.fromhex(enc_flag)
print(len(enc_flag))
iv=enc_flag[:16]
ciphertext=enc_flag[16:]
aes = AES.new(key, AES.MODE_CFB, iv, segment_size=128)
flag = aes.decrypt(ciphertext)
print(flag)
```
```
b'BKSEC{0d44dde71cad8029ceabe4da5fb1614b289289e4a72359a4a681fd8dfcf6827c}'
```
## My opinion
I guess the author want us to recover the iv from the first encryption, knowing ciphertext and plaintext. That iv will be the key
for enc_flag. However, maybe he overprinted the key at the end in chall.py, making it much easier than intended.
