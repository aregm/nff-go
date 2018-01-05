export GOPATH="$HOME"/go
export GOROOT=/opt/go
export YANFF="$GOPATH"/src/github.com/intel-go/yanff
export PATH="$GOPATH"/bin:"$GOROOT"/bin:"$PATH"
export YANFF_CARDS="00:08.0 00:09.0"

# Bind ports to DPDK driver
bindports ()
{
    sudo modprobe uio
    sudo insmod "$YANFF"/dpdk/dpdk-17.08/x86_64-native-linuxapp-gcc/kmod/igb_uio.ko
    sudo "$YANFF"/dpdk/dpdk-17.08/usertools/dpdk-devbind.py --bind=igb_uio $YANFF_CARDS
}

# Bind ports to Linux kernel driver
unbindports ()
{
    sudo "$YANFF"/dpdk/dpdk-17.08/usertools/dpdk-devbind.py --bind=e1000 $YANFF_CARDS
}

# Run pktgen
runpktgen ()
{
    (cd "$YANFF"/dpdk; sudo ./pktgen -c 0xff -n 4 -- -P -m "[1:2].0, [3:4].1" -T)
    rc=$?; if [[ $rc == 0 ]]; then reset; fi
}

# Set up client side machine for NAT example. It initializes two
# network interfaces and sets up default routes to the server
# network. Apache package is installed for apache benchmark program.
natclient ()
{
    sudo nmcli c add type ethernet ifname enp0s8 con-name enp0s8 ip4 192.168.14.2/24
    sudo nmcli c add type ethernet ifname enp0s9 con-name enp0s9 ip4 192.168.24.2/24
    sudo nmcli c up enp0s8
    sudo nmcli c up enp0s9

    sudo ip route add 192.168.16.0/24 via 192.168.14.1 dev enp0s8
    sudo ip route add 192.168.26.0/24 via 192.168.24.1 dev enp0s9

    sudo apt-get install -y apache2
}

# Set up middle machine for NAT example. It initializes two first
# network interfaces for YANFF bindports command and initializes
# second interface pair for use with Linux NAT.
natsetup ()
{
    export YANFF_CARDS="00:08.0 00:0a.0"
    sudo nmcli c add type ethernet ifname enp0s9 con-name enp0s9 ip4 192.168.26.1/24
    sudo nmcli c add type ethernet ifname enp0s16 con-name enp0s16 ip4 192.168.24.1/24
    sudo nmcli c up enp0s9
    sudo nmcli c up enp0s16

    sudo sysctl -w net.ipv4.ip_forward=1
    sudo iptables -t nat -A POSTROUTING -o enp0s9 -j MASQUERADE
    sudo iptables -A FORWARD -i enp0s9 -o enp0s16 -m state --state RELATED,ESTABLISHED -j ACCEPT
    sudo iptables -A FORWARD -i enp0s16 -o enp0s9 -j ACCEPT
}

# Set up server side machine for NAT example. It initializes two
# network interfaces and installs Apache web server.
natserver ()
{
    sudo nmcli c add type ethernet ifname enp0s8 con-name enp0s8 ip4 192.168.16.2/24
    sudo nmcli c add type ethernet ifname enp0s9 con-name enp0s9 ip4 192.168.26.2/24
    sudo nmcli c up enp0s8
    sudo nmcli c up enp0s9

    sudo apt-get install -y apache2
    sudo systemctl enable apache2
    sudo systemctl start apache2
}
