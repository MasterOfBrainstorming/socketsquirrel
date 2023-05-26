#!/usr/bin/env python
import os
import sys
import math
import json
import errno
import paramiko
import argparse
import pandas as pd
import flask as flask
from flask import Flask, render_template
from getpass import getpass
from datetime import datetime
from multiprocessing.pool import ThreadPool

app = Flask(__name__, template_folder='templates')


class htmlDisplay:
    def __init__(self, data):
        self.data = data

    def displayJSON(self):
        return render_template('index.html', data=self.data)


def startFlask(data):
    app.route('/')(htmlDisplay(data).displayJSON)
    app.run()


def verifyUpload(sftp, location, file, host, port):
    return_values = {}
    try:
        sftp.stat(f'{location}{file}')
        return_values[f'{host}:{port}'] = { 
                            'sftp': f'upload {location}{file} success'
                            }
        return return_values
    except Exception as e:
        if e.errno == errno.ENOENT:
            return_values[f'{host}:{port}'] = { 
                            'sftp exception': f'upload {location}{file} failed'
                            }
            return return_values
        

def verifyDownload(host, port, downloaded_file):
    return_values = {}
    for file in os.listdir("."):
        if f"{host}-{downloaded_file}" == file:
            return_values[f'{host}:{port}'] = { 
                            'sftp': f'download {downloaded_file} success'
                            }
            return return_values
    return_values[f'{host}:{port}'] = { 
                    'sftp exception': f'download {downloaded_file} failed'
                    }
    return return_values


def sftpConnect(host, port, username, password, key, timeout, files, location, upload, download):
    print(f" -> [{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}]  {username}@{host}:{port}")
    return_values = {}
    ssh, return_values = sshEstablish(host, port, username, password, key, timeout)
    if return_values:
        return return_values
    try:
        sftp = ssh.open_sftp()
    except Exception as e:
        return_values[f'{host}:{port}'] = {'sftp exception':str(e)}    
    if download:
        server_files = sftp.listdir(path=location)
        if len(server_files) == 0:
            return_values[f'{host}:{port}'] = {'sftp exception': f'no files found at {host}:{location}'}
            return return_values
        for file in files:
            if file in server_files:
                try:
                    sftp.get(f'{location}{file}', f'./{host}-{file}', callback=None)
                    return verifyDownload(host, port, file)
                except Exception as e:
                    return_values[f'{host}:{port}'] = {'sftp exception':str(e)}
        if len(return_values) == 0: 
            return_values[f'{host}:{port}'] = {'sftp exception': f'no files found location:{location} files:{files}'}
        return return_values
            
    if upload:
        for file in files:
            remote_file = file.split('/')[-1]
            try:
                sftp.put(localpath=file, remotepath=f"{location}{remote_file}", callback=None, confirm=False)
                return verifyUpload(sftp, location, remote_file, host, port)
            except Exception as e:
                return_values[f'{host}:{port}'] = {'sftp exception':str(e)}

    sftp.close()
    ssh.close()

    return return_values


def outputWriter(json):
    file_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-socketsquirrel-output.json")
    with open(file_name, 'w') as file:
        file.write(json.replace('\\n"','"'))
    print(f"[+] output written to file: {file_name}")


def sshEstablish(host, port, username, password, key, timeout):
    return_values = {}
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy)
    ssh.load_system_host_keys()
    try:
        ssh.connect(host, port, username=username, password=password, pkey=key, timeout=timeout)
    except Exception as e:
        return_values[f'{host}:{port}'] = {'ssh exception':str(e)}
    return ssh, return_values


def sshConnect(host, port, username, password, key, timeout, command, sudo):
    print(f" -> [{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}]  {username}@{host}:{port}")
    return_values = {}
    ssh, return_values = sshEstablish(host, port, username, password, key, timeout)
    feed_password = False
    if return_values:
        return return_values
    else:
        try:
            if sudo and username != "root":
                command = f"sudo -S -p '' {command}"
                feed_password = password is not None and len(password) > 0
            stdin, stdout, stderr = ssh.exec_command(command)
            if feed_password:
                stdin.write(password + "\n")
                stdin.flush()
            stdin.close()
            return_values[f'{host}:{port}'] = { 
                            'ssh':{
                                'command': command,
                                'output': stdout.readlines(),
                                'error': stderr.readlines(),
                                'retvalue': stdout.channel.recv_exit_status()
                                }
                            }
        except Exception as e:
            return_values[f'{host}:{port}'] = {'ssh exception':str(e)}
    ssh.close()
    return return_values


def engine(cmd_args):
    cmd_args['port'] = [22 if math.isnan(item) else item for item in cmd_args['port']]
    if cmd_args['logging']:
        paramiko.util.log_to_file(f'{datetime.now().strftime("%Y-%m-%d_%H-%M-%S")}-socketsquirrel.log')
    with ThreadPool(cmd_args['threads']) as pool:
        if cmd_args['protocol'] == 'ssh':
            print("[+] starting ssh engine")
            results = pool.starmap(sshConnect, [(host, int(port), cmd_args['username'], cmd_args['password'], cmd_args['key'], cmd_args['timeout'], cmd_args['exec'], cmd_args['sudo']) for host, port in zip(cmd_args['hosts'], cmd_args['port'])])            
        elif cmd_args['protocol'] == 'scp':
            print("[+] starting scp engine")
            results = pool.starmap(sftpConnect, [(host, int(port), cmd_args['username'], cmd_args['password'], cmd_args['key'], cmd_args['timeout'], cmd_args['files'], cmd_args['location'], cmd_args['upload'], cmd_args['download']) for host, port in zip(cmd_args['hosts'], cmd_args['port'])])
        pool.close()
        pool.join()
        outputWriter(json.dumps(results, indent=4))
        if cmd_args['webui']:
            startFlask(results)


def csvParser(cmd_args, hosts):
    print(f"[+] verifying {hosts} headers")
    column_names = []
    correct_headers = {
        1: "hosts",
        2: "hosts,port"
    }
    
    try:
        df = pd.read_csv(hosts)
        headers = df.columns.tolist()
        header_count = len(headers)
        header_values = ','.join(headers).replace(" ","")
    except Exception as e:
        print(f"[!] {e}")
        sys.exit()

    if header_count in correct_headers:
        if header_values in correct_headers[header_count]:
            print(f" -> headers: {header_values}")
        else:
             print(f"[!] incorrect format of headers")
             print(f" -> {header_values}")
             print(" -> correct header options:")
             print(f"{correct_headers}")
             sys.exit()
    else:
        print("[!] invalid count of headers")
        print(f" -> {header_count}")
        sys.exit()
    print(f" -> host: {len(df)}")
    column_names = correct_headers[header_count].split(',')    
    
    for column in column_names:
        cmd_args[column].extend(df[column])

    return cmd_args


def argumentParser():
    print("[+] parsing cmd arguments")
    VERSION  = '1.0'
    parser = argparse.ArgumentParser(
          description=f"""

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
                                Version: {(VERSION)}
        """, 
    formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('command', choices=['ssh', 'scp'], help='The command to execute (ssh or scp)')
    parser.add_argument('-d', '--destination', dest='host', nargs='+', help='Destination IP address or hostname', type=str)
    parser.add_argument('-H','--hosts', dest='hosts', nargs='?', help='File containing IP:port separated by newline, if the port value is missing, default 22', type=str)
    parser.add_argument('-p', '--port', dest='port', nargs='?', help='Will overwrite SSH port, default 22', type=int)
    parser.add_argument('-u', '--user', dest='username', nargs='?', help='SSH username', type=str)
    parser.add_argument('--password', dest='password', nargs='?', help='SSH password', type=str)
    parser.add_argument('--rsa', dest='rsa', nargs='?', help='File location for RSA private key', type=str)    
    parser.add_argument('--enc', dest='enc', action='store_true', help='Add only if the private key requires a password', default=False)
    parser.add_argument('-e', '--execute', dest='execute', nargs='*', help='Owerwrite command to be executed', type=str)
    parser.add_argument('-S', '--sudo', dest='sudo', action='store_true', help='Execute command with sudo', default=False)
    # SCP only
    parser.add_argument('--up', '--upload', dest='upload', action='store_true', help='Files to be uploaded to hosts', default=False)
    parser.add_argument('--dl', '--download', dest='download', action='store_true', help='Files to be downloaded from hosts', default=False)
    parser.add_argument('-f', '--files', dest='files', nargs='+', help='Files to be downloaded from hosts')
    parser.add_argument('-l', '--location', dest='location', nargs='?', help='Files to be uploaded or downloaded from hosts')
    parser.add_argument('-T', '--timeout', dest='timeout', nargs='?', help='Timeout for the connection. Default is 1s', type=int)
    parser.add_argument('-t', '--threads', dest='threads', nargs='?', help='Thread pool count for ssh client, default is 8', type=int)
    parser.add_argument('-L', '--log', dest='logging', action='store_true', help='Enable log file, default False',  default=False)
    parser.add_argument('-w', '--web', dest='webui', action='store_true', help='Enable webUI, default False',  default=False)
    args = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    return args


def optionsPrinter(cmd_args):
        print(f"[+] {cmd_args['protocol']}")
        print(f" -> targets: {cmd_args['hosts']}")
        print(f" -> ports: {cmd_args['port']}")
        print(f" -> username: {cmd_args['username']}")
        print(f" -> password: {cmd_args['password']}")
        print(f" -> private key: {cmd_args['rsa']}")
        print(f" --> encrypted: {cmd_args['enc']}") 
        if cmd_args['protocol'] == 'ssh': 
            print(f" -> sudo: {cmd_args['enc']}")
            print(f" -> command: {cmd_args['enc']}")
        elif cmd_args['protocol'] == 'scp':
            print(f" -> files: {cmd_args['files']}")
            print(f" -> location: {cmd_args['location']}")
            print(f" -> upload: {cmd_args['upload']}")
            print(f" -> download: {cmd_args['download']}")
        print(f" -> timeout: {cmd_args['timeout']}")
        print(f" -> threads: {cmd_args['threads']}")
        print(f" -> threads: {cmd_args['logging']}")


def optionsParser(args):
    print(" -> parsing options")
    cmd_args = {
        'protocol':'',
        'hosts':[],
        'port':[],
        'username':'',
        'password':'',
        'rsa':None,
        'enc':None,
        'key':None,
        'sudo':None,
        'exec':'pwd',
        'timeout':1,
        'threads':8,
        'webui':None,
        'logging':None,
        'files':[],
        'upload':None,
        'download':None,
        'location':''        
    }

    cmd_args['protocol'] = args.command

    if args.host or args.hosts:
        if args.host:
            cmd_args['hosts'] = args.host
        if args.hosts:
            print(f"[+] using hosts file: {args.hosts} contents")
            if os.path.exists(args.hosts):
                print(f" -> {args.hosts} exists")
            else:
                print(f"[!] file does not exist {args.hosts}")
                sys.exit()
            cmd_args = csvParser(cmd_args, args.hosts)
        if args.port:
            print(f"[!] port override: {args.port}")
            cmd_args['port'].clear()
            length = len(cmd_args['hosts'])
            cmd_args['port'].extend([args.port] * length)
        if args.username:
            cmd_args['username'] = args.username
        if args.password or args.rsa:
            if args.password:
                cmd_args['password'] = args.password
            if args.rsa:
                if args.enc:
                    cmd_args['enc'] = args.enc
                cmd_args['rsa'] = args.rsa
        if args.timeout:
            cmd_args['timeout'] = args.timeout
        if args.threads:
            cmd_args['threads'] = args.threads
        if args.logging:
            cmd_args['logging'] = args.logging
        if args.webui:
            cmd_args['webui'] = args.webui

    else:
        print(f"[!] no hosts were provided")

    if args.command == 'ssh': 
        if args.sudo:
            print(f"[!] privilege override: {args.sudo}")
            cmd_args['sudo'] = args.sudo
        if args.execute:
             print(f"[!] command override: {args.execute}")
             cmd_args['exec'] = ' '.join(args.execute)
             print(cmd_args['exec'])
        
    elif args.command == 'scp':
        if not args.location:
            print('[!] location must be set when using scp')
            sys.exit()
        elif args.location.endswith('/'):
            cmd_args['location'] = args.location
        else:
            cmd_args['location'] = args.location + '/'
        if (args.upload or args.download) and (args.files):
            if args.upload:
                cmd_args['upload'] = args.upload
                for file in args.files:
                    if os.path.exists(file):
                        cmd_args['files'] = args.files
                    else:
                        print(f"[!] file {file} does not exist!")

                if len(cmd_args['files']) == 0:
                    print("[!] no files to upload")
                    sys.exit()
            if args.download:
                cmd_args['download'] = args.download
                cmd_args['files'] = args.files
        else:
            print("[!] files and download or upload must be defined")
            sys.exit()
    else:
        print("[!] error occured during parsing options")
    
    return cmd_args


def main(cmd_args):
    optionsPrinter(cmd_args)
    if cmd_args['rsa']:
        if cmd_args['enc']:
            print('[!] unlock rsa key')
            passphrase = getpass(prompt=' -> password: ', stream=None)
            cmd_args['key'] = paramiko.RSAKey.from_private_key_file(cmd_args['rsa'], password=passphrase)
        else:
            cmd_args['key'] = paramiko.RSAKey.from_private_key_file(cmd_args['rsa'], None)
    if ((cmd_args['password'] or cmd_args['rsa']) and not cmd_args['username']):
             print("[!] missing username")
             cmd_args['username'] = input(" -> username: ")
    elif (cmd_args['username'] and not cmd_args['password'] or ((cmd_args['username'] and cmd_args['rsa'] and cmd_args['sudo']) and not cmd_args['password'])):
            print("[!] missing password")
            cmd_args['password'] = getpass(prompt=' -> password: ', stream=None)
    else:    
        engine(cmd_args)
    print("[+] execution finished")


if __name__ == "__main__":
    args = argumentParser()
    cmd_args = optionsParser(args)
    main(cmd_args)

