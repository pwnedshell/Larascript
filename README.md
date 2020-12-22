<pre>
 _                                           _         _
| |      __ _  _ __   __ _  ___   ___  _ __ (_) _ __  | |_
| |     / _` || '__| / _` |/ __| / __|| '__|| || '_ \ | __|
| |___ | (_| || |   | (_| |\__ \| (__ | |   | || |_) || |_
|_____| \__,_||_|    \__,_||___/ \___||_|   |_|| .__/  \__|
                                               |_|

Authors: @pwnedshell & @rsgbengi 
</pre>
<p align="center">
    <img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/PwnedShell/Larascript?style=for-the-badge">
    <img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/PwnedShell/Larascript?style=for-the-badge">
    <img alt="GitHub" src="https://img.shields.io/github/license/pwnedshell/Larascript?style=for-the-badge">
</p>
<p align="center">
    <img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/pwnedshell?style=for-the-badge">
    <img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/rsgbengi?style=for-the-badge">
</p>
<br> 

<h2>📌 What its Larascript?</h2>
Larascript is a script which take advantage from <code>CVE-2018-15133</code> and can execute remote commands if a vulnerable Laravel app is exposed. You can send commands and get response such as get <code>cat /etc/passwd</code>. But you also can ask for a shell so it gives you a reverse shell. It has some argument personalitation so you can specify what type of reverse shell you get (bash or sh), what reverse shell language use to retrieve the shell (php, bash, mkfifo, python...) or the laravel RCE method (1,2,3 or 4). It also provides a good shell interaction and references to the shell treatment or linux privilege escalation.

<h2>🧨 CVE-2018-15133</h2>
In Laravel Framework through 5.5.40 and 5.6.x through 5.6.29, remote code execution might occur as a result of an unserialize call on a potentially untrusted X-XSRF-TOKEN value. This involves the decrypt method in Illuminate/Encryption/Encrypter.php and PendingBroadcast in gadgetchains/Laravel/RCE/3/chain.php in phpggc. The attacker must know the application key, which normally would never occur, but could happen if the attacker previously had privileged access or successfully accomplished a previous attack.

<h2>📦 Install</h2>
<pre>
git clone https://github.com/PwnedShell/Larascript
pip3 install -r requirements.txt
</pre>

<h2>📘 Usage</h2>
Required params are the vulnerable <strong>url</strong> and the <strong>app_key</strong> in base64. See <code>larascript.py -h</code>.<br><br>
<pre>
usage: larascript.py [-h] -k APPKEY [-c COMMAND] [-m {1,2,3,4,5}] [-s {bash,python,perl,php,ruby,nc,mkfifo,lua,java}]
                 [-t {bash,sh}] [-p PORT] [-P LPORT] [-U LHOST]
                 url
</pre>
Send the command <code>whoami</code><br><br>
<p align="center">
<img width="80%" src="https://github.com/rsgbengi/DreamTeamArmy/blob/main/Intrusion/Laravel%20CVE-2018-15133/pictures/command-poc.png">
</p>
Get a reverse shell using mkfifo payload. Setting the lhost to our local machine<br><br>
<p align="center">
<img width="80%" src="https://github.com/rsgbengi/DreamTeamArmy/blob/main/Intrusion/Laravel%20CVE-2018-15133/pictures/shell-poc1.png">
</p>

<h2>📎 References</h2>
<ul>
 <li><a href="https://www.cvedetails.com/cve/CVE-2018-15133/">CVE-2018-15133</a></li>
 <li><a href="https://github.com/aljavier/exploit_laravel_cve-2018-15133">Aljavier exploit</a></li>
 <li><a href="https://github.com/kozmic/laravel-poc-CVE-2018-15133">Kozmic POC</a></li>
 <li><a href="https://github.com/ambionics/phpggc">Phpggc</a></li>
 <li><a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md">Payload all the things</a></li>
</ul>
