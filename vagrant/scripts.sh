export GOROOT=/opt/go
export NFF_GO="$HOME"/nff-go
export PATH="$HOME"/go/bin:"$GOROOT"/bin:"$PATH"
export MAKEFLAGS="-j 4"
export NFF_GO_CARDS="00:06.0 00:07.0"
export DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
export CARD1=ens6
export CARD2=ens7

# Bind ports to DPDK driver
bindports ()
{
    sudo modprobe uio
    sudo insmod "$NFF_GO"/dpdk/dpdk/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
    sudo "$NFF_GO"/dpdk/dpdk/usertools/dpdk-devbind.py --bind=igb_uio $NFF_GO_CARDS
}

# Bind ports to Linux kernel driver
unbindports ()
{
    sudo "$NFF_GO"/dpdk/dpdk/usertools/dpdk-devbind.py --bind=e1000 $NFF_GO_CARDS
}

# Run pktgen
runpktgen ()
{
    (cd "$NFF_GO"/dpdk; sudo ./pktgen -c 0xff -n 4 -- -P -m "[1:2].0, [3:4].1" -T)
    rc=$?; if [[ $rc == 0 ]]; then reset; fi
}

# Perform one-time configuration needed for NAT test
# machine. It installs Apache web server.
setuptesthost ()
{
    setupdocker

    if [ $DISTRO == Ubuntu ]; then
        sudo apt-get install -y apache2
        sudo systemctl enable apache2
        sudo systemctl start apache2
    elif [ $DISTRO == Fedora ]; then
        sudo dnf -y install httpd
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
    elif [ $DISTRO == Fedora ]; then
        sudo dnf config-manager --add-repo https://download.docker.com/linux/fedora/docker-ce.repo
        sudo dnf -y install docker-ce
    fi

    sudo gpasswd -a vagrant docker
    sudo sed -i -e 's,ExecStart=/usr/bin/dockerd -H unix://,ExecStart=/usr/bin/dockerd,' /lib/systemd/system/docker.service
    sudo sed -i -e 's,ExecStart=/usr/bin/dockerd -H fd://,ExecStart=/usr/bin/dockerd,' /lib/systemd/system/docker.service
    sudo sed -i -e 's,ExecStart=/usr/bin/dockerd -H unix://,ExecStart=/usr/bin/dockerd,' /etc/systemd/system/docker.service
    sudo sed -i -e 's,ExecStart=/usr/bin/dockerd -H fd://,ExecStart=/usr/bin/dockerd,' /etc/systemd/system/docker.service

    if [ ! -z "${http_proxy}" ]
    then
        sudo mkdir /etc/systemd/system/docker.service.d
        sudo sh -c 'cat > /etc/systemd/system/docker.service.d/http-proxy.conf <<EOF
[Service]
Environment="HTTP_PROXY=${http_proxy}"
EOF'
    fi

    sudo mkdir /etc/docker
    sudo sh -c 'cat > /etc/docker/daemon.json <<EOF
{
    "hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"],
    "ipv6": true,
    "fixed-cidr-v6": "fdd0::/64"
}
EOF'

    sudo systemctl enable docker.service
    sudo systemctl daemon-reload
    sudo systemctl restart docker.service

    sudo docker pull robbertkl/ipv6nat
    sudo docker run -d --restart=always -v /var/run/docker.sock:/var/run/docker.sock:ro --privileged --net=host robbertkl/ipv6nat
}
