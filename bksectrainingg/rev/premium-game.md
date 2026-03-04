## Description
[Battle_for_Hustonia.zip](https://training.bksec.vn/apiv2/files/local/6Pzic9IEthYCBA82iSsgS?iat=1772596800&sig=AlbUKmf3s7tIrWLvo6MLDNz2oXCywYa5VTHnv4j13qo)
## My solution
I ran the exe file first to see what would happen.

<img width="507" height="424" alt="image" src="https://github.com/user-attachments/assets/c21c4dad-b36a-415e-a01d-407bb5f62e9f" />

The licence key is required to get the locked item. After I typed a random key, it showed `INVALID KEY`. I open the file in Ghidra, and search for the string `INVALID KEY`
(it must be near the check function).

<img width="509" height="373" alt="image" src="https://github.com/user-attachments/assets/443a8a58-1f57-4a0b-bb84-d1b94aa989a3" />

After locating it, I move to that function. 

<img width="562" height="360" alt="image" src="https://github.com/user-attachments/assets/f5909a1d-f223-4a9b-bfb0-4b37234a9460" />

The function `FUN_00405596` is right above the string, it should be the check function. Let's take a look.
```
undefined8 FUN_00405596(ulong param_1)

{
  long lVar1;
  undefined8 uVar2;
  ulong uVar3;
  byte *pbVar4;
  long in_FS_OFFSET;
  ulong local_50;
  int local_48 [14];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  lVar1 = std::__cxx11::string::length();
  if (lVar1 == 0xc) {
    local_48[0] = 1;
    local_48[1] = 0x21;
    local_48[2] = 0x24;
    local_48[3] = 0x27;
    local_48[4] = 0x2d;
    local_48[5] = 0x25;
    local_48[6] = 0x28;
    local_48[7] = 0x21;
    local_48[8] = 0x21;
    local_48[9] = 0x2b;
    local_48[10] = 0x3c;
    local_48[0xb] = 0x48;
    local_50 = 0;
    while( true ) {
      uVar3 = std::__cxx11::string::length();
      if (uVar3 <= local_50) break;
      pbVar4 = (byte *)std::__cxx11::string::operator[](param_1);
      if ((uint)(*pbVar4 ^ 0x55) + (int)local_50 * 4 != local_48[local_50]) {
        uVar2 = 0;
        goto LAB_00405698;
      }
      local_50 = local_50 + 1;
    }
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
LAB_00405698:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return uVar2;
}
```

The upper code can be reversed by this code to find the key:
```
arr = [0x01, 0x21, 0x24, 0x27, 0x2d, 0x25, 0x28, 0x21, 0x21, 0x2b, 0x3c, 0x48]
key = ""

for i in range(12):
    c = (arr[i] - (i * 4)) ^ 0x55
    key += chr(c)

print(key)
```
```
THINHDEPTRAI
```


