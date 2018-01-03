To execute vagrant with this Vagrantfile it is recommended to use
VirtualBox 5.2 or higher and vagrant 2.0.1 or higher. Additionally, if
you use http proxy, it is necessary to install vagrant proxyconf
plugin.

Use this page to add VirtualBox repository to your Linux installation
https://www.virtualbox.org/wiki/Linux_Downloads

Download Vagrant installation package from this page
https://www.vagrantup.com/downloads.html. For Ubuntu use Debian .deb
file and install it with command

        sudo dpkg -i vagrant_2.0.1_x86_64.deb

To add a proxyconf plugin to your vagrant installation, run the
following command for normal user

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
