For VM specific section see below. Libvirt is the default VM now and
it requires an additional vagrant plugin.

Download Vagrant installation package from this page
https://www.vagrantup.com/downloads.html. For Ubuntu use Debian .deb
file and install it with command

        sudo dpkg -i vagrant_2.0.3_x86_64.deb

A plugin is required to restart VMs after provisioning:

        vagrant plugin install vagrant-reload

If you need to work through http proxy, it is necessary to install
vagrant-proxyconf plugin:

        vagrant plugin install vagrant-proxyconf

After all prerequisites are done, you can bring VMs with command

        vagrant up

This script supports the following parameters: VM_GROUP_SIZE,
VM_TOTAL_NUMBER, VM_LINKS_NUMBER:

* VM_GROUP_SIZE - specifies how many VMs are connected
  together. Default value is 2, which means that VMs are connected
  together in pairs: VM-VM. If this value is greater than 2, then VMs
  are connected linearly like this: VM-VM-VM-...-VM.
* VM_TOTAL_NUMBER - specifies how many VMs to create. Default value is
  2, which means that script creates one VM pair. It is better to
  specify VM_TOTAL_NUMBER divisable by VM_GROUP_SIZE or the last group
  of VMs may be less than VM_GROUP_SIZE.
* VM_LINKS_NUMBER - number of network connections between each VM in a
  group. Default value is 2, which means that VMs are connected with
  two network links: e.g. VM=VM=VM.

so the following command creates two groups of VMs connected with
single link: VM-VM-VM VM-VM.

       VM_GROUP_SIZE=3 VM_LINKS_NUMBER=1 VM_TOTAL_NUMBER=5 vagrant up

See wiki page https://github.com/intel-go/nff-go/wiki/NAT-example for
instructions on how to configure virtual machines to run NFF-GO NAT
example.

## Libvirt/Qemu/KVM specific secion

It is necessary to install libvirt vagrant plugin like this:

    vagrant plugin install vagrant-libvirt

Current setup creates VM in storage pool named 'images'. To create
such pool use commands like this:

    virsh pool-define-as images dir --target /localdisk/libvirt
    virsh pool-start images

VMs are connected via virtual networks which are created as UDP
tunnes. For this it is necessary to allocate a sufficient number of
UDP ports on localhost. Default port starting number is 12345. After
this port VMs use ports continuously with total number equal to
(VM_LINKS_NUMBER+1)*VM_TOTAL_NUMBER. If any of these ports are already
occupied (e.g. some other use already created VMs with this starting
port number), some network connections will not work. To change
starting port number you can define VM_TUNNEL_PORT_BASE variable
before using 'vagrant up' command.

UDP tunnels were found to be unreliable because in some cases packet
trasmisison stopped for an unknown reason. Another way to connect VMs
is to create virtual bridges (switches) for each pair of network
interfaces. Unfortunatelly this has to be done by hands necause
vagrant script doesn't allow to create multiple networks.

To create a new birdge network use the folowing XML template (change
DPDK_1 and dpdkbr1 identifiers for subsequent connections).

    <network ipv6='yes'>
      <name>DPDK_1</name>
      <bridge name='dpdkbr1' stp='off' delay='0'/>
    </network>

use command like

    virsh net-define dpdk1.xml
    virsh net-start DPDK_1

to create every bridge. After that use command like

    virsh edit nff-go-0

to edit every VM configuration and apply changes like this:

    --- vm.udp      2018-05-31 10:05:21.265484863 -0500
    +++ vm.bridge   2018-05-31 10:07:01.669059781 -0500
    @@ -38,19 +38,15 @@
           <model type='virtio'/>
           <address type='pci' domain='0x0000' bus='0x00' slot='0x05' function='0x0'/>
         </interface>
    -    <interface type='udp'>
    +    <interface type='network'>
           <mac address='52:54:00:41:32:82'/>
    -      <source address='127.0.0.1' port='33312'>
    -        <local address='127.0.0.1' port='33303'/>
    -      </source>
    +      <source network='DPDK_1'/>
           <model type='e1000'/>
           <address type='pci' domain='0x0000' bus='0x00' slot='0x06' function='0x0'/>
         </interface>
    -    <interface type='udp'>
    +    <interface type='network'>
           <mac address='52:54:00:39:19:e6'/>
    -      <source address='127.0.0.1' port='33313'>
    -        <local address='127.0.0.1' port='33304'/>
    -      </source>
    +      <source network='DPDK_2'/>
           <model type='e1000'/>
           <address type='pci' domain='0x0000' bus='0x00' slot='0x07' function='0x0'/>
         </interface>

For example three VMs with two connections between each pair would be
connected like this:

    +----------+<---DPDK_1--->+----------+<---DPDK_3--->+----------+
    | nff-go-0 |              | nff-go_1 |              | nff-go-2 |
    +----------+<---DPDK_2--->+----------+<---DPDK_4--->+----------+

After all changes are done you can still use vagrant commands

    vagrant up nff-go-0
    vagrant ssh nff-go-0

to start a VM and access it remotely. Vagrant doesn't interfere with
edited VM configuration.

## VirtualBox specific section

In our experience VirtualBox hangs and crashes too often. Its Intel
network cards emulation doesn't support VLAN tags. That is why we had
to switch to Libvirt/Qemu/KVM alternative.

To execute vagrant with this Vagrantfile it is recommended to use
VirtualBox 5.2 or higher and vagrant 2.0.1 or higher. Additionally, if
you use http proxy, it is necessary to install vagrant proxyconf
plugin.

Use this page to add VirtualBox repository to your Linux installation
https://www.virtualbox.org/wiki/Linux_Downloads
