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
              Opt::RHOST("192.168.1.141"),
              Opt::RPORT(20002),
      ], self.class)
   end

   def exploit
    # exploit code goes here!
   end
end
