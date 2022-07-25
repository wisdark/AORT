<img src="https://raw.githubusercontent.com/D3Ext/SDomDiscover/main/SDomDiscover.png" width=1100 height=500>

`A easy-to-use python tool to perform dns recon with multiple options`

## ⭕ Installation:
It can be installed in any OS with python3

> Manual installation
```sh
git clone https://github.com/D3Ext/SDomDiscover
cd SDomDiscover
pip3 install -r requirements.txt
```

> One-liner
```sh
git clone https://github.com/D3Ext/SDomDiscover && cd SDomDiscover && pip3 install -r requirements.txt && python3 SDomDiscover.py
```

## ⭕ Usage:

> Common usages

> To see the help panel and other parameters
```sh
python3 SDomDiscover.py -h
```

> Main usage of the tool to dump the valid domains in the SSL certificate 
```sh
python3 SDomDiscover.py -d example.com
```

> Used to perform all the queries and recognizement
```sh
python3 SDomDiscover.py -d domain.com --all
```
## ⭕ Features:

:ballot_box_with_check: Dump valid subdomains 

:ballot_box_with_check: Store subdomains in a file

:ballot_box_with_check: A lot of extra queries to enumerate the DNS port

## ⭕ Demo:

> Simple query to find valid subdomains
<img src="https://raw.githubusercontent.com/D3Ext/SDomDiscover/main/demo.png">

**If you consider this project has been useful, I would really appreciate supporting me by giving this repo a star or buying me a coffee.**

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://www.buymeacoffee.com/d3ext)

Copyright © 2022, *D3Ext*
