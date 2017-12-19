To execute vagrant with this Vagrantfile it is recommended to use VirtualBox 5.2
or higher and vagrant 2.0.1 or higher. Additionally, if you use http proxy, it is necessary
to install vagrant proxyconf plugin.

Use this page to add VirtualBox repository to your Linux installation https://www.virtualbox.org/wiki/Linux_Downloads

Download Vagrant installation package from this page https://www.vagrantup.com/downloads.html. For Ubuntu use Debian .deb file and install it with command

        sudo dpkg -i vagrant_2.0.1_x86_64.deb

To add a proxyconf plugin to your vagrant installation, run the following command for normal user

        vagrant plugin install vagrant-proxyconf

After all prerequisites are done, you can bring VMs with command

        vagrant up
