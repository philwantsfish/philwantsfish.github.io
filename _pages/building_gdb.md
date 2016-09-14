---
layout: single
title: Exploit Exercises - Building GDB
permalink: /building_gdb/
---
---

The following is instructions for building GDB for the exploit exercises fusion VM.

## Fixing the repository locations

Modify the `/etc/apt/source.list` to be:

```
deb http://old-releases.ubuntu.com/ubuntu/ oneiric main
deb-src http://old-releases.ubuntu.com/ubuntu/ oneiric main
deb http://old-releases.ubuntu.com/ubuntu/ oneiric-updates main
deb-src http://old-releases.ubuntu.com/ubuntu/ oneiric-updates main
deb http://old-releases.ubuntu.com/ubuntu/ oneiric universe
deb-src http://old-releases.ubuntu.com/ubuntu/ oneiric universe
deb http://old-releases.ubuntu.com/ubuntu/ oneiric-updates universe
deb-src http://old-releases.ubuntu.com/ubuntu/ oneiric-updates universe
deb http://old-releases.ubuntu.com/ubuntu oneiric-security main
deb-src http://old-releases.ubuntu.com/ubuntu oneiric-security main
deb http://old-releases.ubuntu.com/ubuntu oneiric-security universe
deb-src http://old-releases.ubuntu.com/ubuntu oneiric-security universe
```

## Prerequisites

Update and install the prerequisite libraries

```
apt-get update
apt-get install libncurses5-dev libreadline-dev texinfo
apt-get install python3 python3-dev
```

## Build GDB

Obtain and build the source code

```
mv /usr/bin/python /usr/bin/python.bak
ln /usr/bin/python3 /usr/bin/python

wget https://ftp.gnu.org/gnu/gdb/gdb-7.9.tar.xz
tar -xvf gdb-7.9.tar.xz
cd gdb-7.9
./configure --with-python
make
make -C gdb install
```

Replace gdb with the newer one

```
rm /usr/bin/gdb
ln -s /usr/local/bin/gdb /usr/bin/gdb
```

Test our installation worked

```
$ gdb -q
(gdb) python import sys
(gdb) python print(sys.version)
3.2.2 (default, Oct 20 2012, 03:05:40)
[GCC 4.6.1]
(gdb)
```
