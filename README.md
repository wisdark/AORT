# All in One Recon Tool

`A easy-to-use python tool to perform dns recon, subdomain enumeration and much more`

The purpouse of this tool is helping bug bounters and pentester during reconnaissance

If you want to know more about the tool you can read my own [post](https://d3ext.github.io/aort) in my blog   

## Installation:
It can be installed in any system with python3

You can easily install AORT using pip:

```sh
pip3 install aort
```

If you want to install it from source:
```sh
git clone https://github.com/D3Ext/AORT
cd AORT
pip3 install -r requirements.txt
```

> One-liner
```sh
git clone https://github.com/D3Ext/AORT && cd AORT && pip3 install -r requirements.txt && python3 AORT.py
```

## Usage:

> Common usages

> If installed with pip3:
```sh
aort
```

> To see the help panel and other parameters
```sh
python3 AORT.py -h
```

> Main usage of the tool to dump the valid domains in the SSL certificate 
```sh
python3 AORT.py -d example.com
```

> Used to perform all the queries and recognizement
```sh
python3 AORT.py -d domain.com --all
```
## Features:

:ballot_box_with_check: Enumerate subdomains using passive techniques 

:ballot_box_with_check: A lot of extra queries to enumerate the DNS

:ballot_box_with_check: Domain Zone trasnfer attack

:ballot_box_with_check: WAF type detection

:ballot_box_with_check: Subdomain Takeover checker

:ballot_box_with_check: Wayback machine support to enumerate endpoints

:ballot_box_with_check: Email harvesting

## Demo:

> Simple query to find valid subdomains
<img src="https://raw.githubusercontent.com/D3Ext/AORT/main/demo.png">

## Third part

The tool uses different services to get subdomains in different ways

The WAF detector was modified and addapted from [CRLFSuite](https://github.com/Nefcore/CRLFsuite) concept

All DNS queries are scripted in python at 100%

Email harvesting using Proxycrawl API with personal token (you can register a free account with 100 uses)

## Extra

**If you consider this project has been useful, I would really appreciate supporting me by giving this repo a star or buying me a coffee.**

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/d3ext)

Copyright © 2022, *D3Ext*
