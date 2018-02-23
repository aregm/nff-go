export GOPATH="$HOME"/go
export GOROOT=/opt/go
export NFF_GO="$GOPATH"/src/github.com/intel-go/nff-go
export PATH="$GOPATH"/bin:"$GOROOT"/bin:"$PATH"
export MAKEFLAGS="-j 4"
export NFF_GO_CARDS="00:08.0 00:09.0"
export DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
if [ $DISTRO == Ubuntu ]; then
    export CARD1=enp0s8
    export CARD2=enp0s9
elif [ $DISTRO == Fedora ]; then
    export CARD1=eth1
    export CARD2=eth2
fi

# Bind ports to DPDK driver
bindports ()
{
    sudo modprobe uio
    sudo insmod "$NFF_GO"/dpdk/dpdk-17.08/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
    sudo "$NFF_GO"/dpdk/dpdk-17.08/usertools/dpdk-devbind.py --bind=igb_uio $NFF_GO_CARDS
}

# Bind ports to Linux kernel driver
unbindports ()
{
    sudo "$NFF_GO"/dpdk/dpdk-17.08/usertools/dpdk-devbind.py --bind=e1000 $NFF_GO_CARDS
}

# Run pktgen
runpktgen ()
{
    (cd "$NFF_GO"/dpdk; sudo ./pktgen -c 0xff -n 4 -- -P -m "[1:2].0, [3:4].1" -T)
    rc=$?; if [[ $rc == 0 ]]; then reset; fi
}

# Perform transient NAT client machine configuration. It initializes
# two network interfaces and sets up default routes to the server
# network.
natclient ()
{
    sudo ip route add 192.168.16.0/24 via 192.168.14.1 dev $CARD1
    sudo ip route add 192.168.26.0/24 via 192.168.24.1 dev $CARD2
}

# Perform one-time configuration needed for NAT client test
# machine. For it apache package is installed for apache benchmark
# program.
setupnatclient ()
{
    sudo nmcli c add type ethernet ifname $CARD1 con-name $CARD1 ip4 192.168.14.2/24
    sudo nmcli c add type ethernet ifname $CARD2 con-name $CARD2 ip4 192.168.24.2/24
    sudo nmcli c up $CARD1
    sudo nmcli c up $CARD2

    natclient

    if [ $DISTRO == Ubuntu ]; then
        sudo apt-get install -y apache2
    elif [ $DISTRO == Fedora ]; then
        sudo dnf -y install httpd
    fi
}

# Perform transient configuration for NAT middle machine. It
# initializes two first network interfaces for NFF-GO bindports
# command and initializes second interface pair for use with Linux
# NAT. In this setup eth4(enp0s16) is connected to server (public
# network) and eth2(enp0s9) is connected to client (private network).
natmiddle ()
{
    export NFF_GO_CARDS="00:08.0 00:0a.0"
    if [ $DISTRO == Ubuntu ]; then
        export CARD1=enp0s9
        export CARD2=enp0s16
    elif [ $DISTRO == Fedora ]; then
        export CARD1=eth2
        export CARD2=eth4
    fi

    bindports

    sudo sysctl -w net.ipv4.ip_forward=1

    if [ $DISTRO == Ubuntu ]; then
        sudo iptables -t nat -A POSTROUTING -o $CARD2 -j MASQUERADE
        sudo iptables -A FORWARD -i $CARD2 -o $CARD1 -m state --state RELATED,ESTABLISHED -j ACCEPT
        sudo iptables -A FORWARD -i $CARD1 -o $CARD2 -j ACCEPT
    fi
}

# Perform one-time configuration needed for NAT middle machine. On
# Fedora we use firewall daemon to permanently record IP forwarding
# rules.
setupnatmiddle ()
{
    natmiddle

    sudo nmcli c add type ethernet ifname $CARD1 con-name $CARD1 ip4 192.168.24.1/24
    sudo nmcli c add type ethernet ifname $CARD2 con-name $CARD2 ip4 192.168.26.1/24
    sudo nmcli c up $CARD1
    sudo nmcli c up $CARD2

    if [ $DISTRO == Fedora ]; then
        sudo firewall-cmd --permanent --direct --add-rule ipv4 nat POSTROUTING 0 -o $CARD2 -j MASQUERADE
        sudo firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i $CARD2 -o $CARD1 -m state --state RELATED,ESTABLISHED -j ACCEPT
        sudo firewall-cmd --permanent --direct --add-rule ipv4 filter FORWARD 0 -i $CARD1 -o $CARD2 -j ACCEPT
        sudo firewall-cmd --direct --add-rule ipv4 nat POSTROUTING 0 -o $CARD2 -j MASQUERADE
        sudo firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i $CARD2 -o $CARD1 -m state --state RELATED,ESTABLISHED -j ACCEPT
        sudo firewall-cmd --direct --add-rule ipv4 filter FORWARD 0 -i $CARD1 -o $CARD2 -j ACCEPT
    fi
}

# Perform one-time configuration needed for NAT server side
# machine. It installs Apache web server.
setupnatserver ()
{
    sudo nmcli c add type ethernet ifname $CARD1 con-name $CARD1 ip4 192.168.16.2/24
    sudo nmcli c add type ethernet ifname $CARD2 con-name $CARD2 ip4 192.168.26.2/24
    sudo nmcli c up $CARD1
    sudo nmcli c up $CARD2

    if [ $DISTRO == Ubuntu ]; then
        sudo apt-get install -y apache2
        sudo systemctl enable apache2
        sudo systemctl start apache2
    elif [ $DISTRO == Fedora ]; then
        sudo dnf -y install httpd
        sudo firewall-cmd --permanent --add-service=http
        sudo firewall-cmd --add-service=http
        sudo systemctl enable httpd
        sudo systemctl start httpd
    fi

    sudo dd if=/dev/zero of=/var/www/html/10k.bin bs=1 count=10240
    sudo dd if=/dev/zero of=/var/www/html/100k.bin bs=1 count=102400
    sudo dd if=/dev/zero of=/var/www/html/1m.bin bs=1 count=1048576
}

# Set up docker daemon, this is needed for automated testing.
setupdocker ()
{
    if [ $DISTRO == Ubuntu ]; then
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
        sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
        sudo apt-get update
        sudo apt-get install -y docker-ce
        sudo gpasswd -a ubuntu docker
        sudo sed -i -e 's,ExecStart=/usr/bin/dockerd -H fd://,ExecStart=/usr/bin/dockerd,' /lib/systemd/system/docker.service
    elif [ $DISTRO == Fedora ]; then
        sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        sudo dnf -y install docker-ce
        sudo gpasswd -a vagrant docker
        sudo firewall-cmd --permanent --add-port=2375/tcp
        sudo firewall-cmd --add-port=2375/tcp
    fi

    sudo sh -c 'cat <<EOF > /etc/docker/daemon.json
{
    "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"]
}
EOF'
    sudo systemctl enable docker.service
    sudo systemctl daemon-reload
    sudo systemctl restart docker.service
}
