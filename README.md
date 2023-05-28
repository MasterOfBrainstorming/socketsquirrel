# socketsquirrel
Python script made with Paramiko to SSH multiple endpoint and execute commands, upload and download files. Designed for lazy professionals in a hurry to escape client location to catch few coldones.


         _____            _        _    _____             _               _
        / ____|          | |      | |  / ____|           (_)             | |
       | (___   ___   ___| | _____| |_| (___   __ _ _   _ _ _ __ _ __ ___| |
        \___ \ / _ \ / __| |/ / _ \ __|\___ \ / _` | | | | | '__| '__/ _ \ |
        ____) | (_) | (__|   <  __/ |_ ____) | (_| | |_| | | |  | | |  __/ |
       |_____/ \___/ \___|_|\_\___|\__|_____/ \__, |\__,_|_|_|  |_|  \___|_|
        _________________________________________| |________________________
        +++++++++++++++++++++++++++++++++++++++++|_|++++++++++++++++++++++++
        ©2023 masterofbrainstorming

                 Tool to help loop multiple SSH endpoints with ease.
                    Created for the breed of lazy auditors
                        Access, Upload, Dowload, Execute.
                                Version: 1.0

## Installation

The script will require pandas, paramiko, argparse and flask in addition to python standard libraries

```bash
pip install -r requirements.txt
```

## Commanline arguments

```bash
positional arguments:
  {ssh,scp}             The command to execute (ssh or scp)

optional arguments:
  -h, --help            show this help message and exit
  -d HOST [HOST ...], --destination HOST [HOST ...]
                        Destination IP address or hostname
  -H [HOSTS], --hosts [HOSTS]
                        File containing IP:port separated by newline, if the port value is missing, default 22
  -p [PORT], --port [PORT]
                        Will overwrite SSH port, default 22
  -u [USERNAME], --user [USERNAME]
                        SSH username
  --password [PASSWORD]
                        SSH password
  --rsa [RSA]           File location for RSA private key
  --enc                 Add only if the private key requires a password
  -e [EXECUTE ...], --execute [EXECUTE ...]
                        Owerwrite command to be executed
  -S, --sudo            Execute command with sudo
  --up, --upload        Files to be uploaded to hosts
  --dl, --download      Files to be downloaded from hosts
  -f FILES [FILES ...], --files FILES [FILES ...]
                        Files to be downloaded from hosts
  -l [LOCATION], --location [LOCATION]
                        Files to be uploaded or downloaded from hosts
  -T [TIMEOUT], --timeout [TIMEOUT]
                        Timeout for the connection. Default is 1s
  -t [THREADS], --threads [THREADS]
                        Thread pool count for ssh client, default is 8
  -L, --log             Enable log file, default False
  -w, --web             Enable webUI, default False
```

## Usage:

The script will require certain parameters in order to work. 
You must specify: 
- positional argument (current implementation has only ssh and scp implentation)
- host or hostfile (go to examples/examples.csv)
- port (either supplied in hostfile or as cmd argument)
- password (either prompted or supplied via cmd) or private key (file destination)

### Optional arguments
```
  -S, --sudo            Execute command with sudo
  -T [TIMEOUT], --timeout [TIMEOUT]
                        Timeout for the connection. Default is 1s
  -t [THREADS], --threads [THREADS]
                        Thread pool count for ssh client, default is 8
  -L, --log             Enable log file, default False
  -w, --web             Enable webUI, default False
```

### SSH

Using username, password and port:
```bash
socketsquirrel.py ssh -d <ip> <ip2> <ip3> -p 2222 -u example --password mypassword
[+] parsing cmd arguments
 -> parsing options
[!] port override: 2222
[+] ssh
 -> targets: [<ip>, <ip2>, <ip3>]
 -> ports: [22, 22]
 -> username: example
 -> password: mypassword
 -> private key: None
 --> encrypted: None
 -> sudo: None
 -> command: pwd
 -> timeout: 1
 -> threads: 8
 -> webui: None
```

Using rsa without passphrase:
```bash
socketsquirrel.py ssh -d <ip> <ip2> <ip3> -p 22 -u example --rsa
```

Using rsa with passphrase:
```bash
socketsquirrel.py ssh -d <ip> <ip2> <ip3> -p 22 -u example --rsa --enc
```

Using commands:
```bash
socketsquirrel.py ssh -d <ip> <ip2> <ip3> -p 22 -u example --password mypassword -e 'cat /etc/passwd | grep $(whoami)'
```

Using commands with sudo:
```bash
socketsquirrel.py ssh -d <ip> <ip2> <ip3> -p 22 -u example --password mypassword -e 'whoami' -S
```

Using webui to display results:
```bash
socketsquirrel.py ssh -d <ip> <ip2> <ip3> -p 22 -u example --password mypassword -e 'whoami' -S -w
```

Using hosts file:
```bash
socketsquirrel.py ssh -H examples/example.csv -u example --password mypassword
```


### SCP

Uploading files to location /tmp:
```bash
python3.9 socketsquirrel.py scp -d <ip> <ip2> <ip3> -u example --password mypassword -p 22 -f file.txt --up -l '/tmp'
```

Downloading files from location /tmp:
```bash
python3.9 socketsquirrel.py scp -d <ip> <ip2> <ip3> -u example --password mypassword -p 22 -f file.txt --dl -l '/tmp'
```


### WebUI
Made with flask. The webserver will start listening on localhost:5000 and display results
![image](https://github.com/MasterOfBrainstorming/socketsquirrel/assets/16796116/8a9b812c-426f-4b10-a125-f2f279e3c5dd)
