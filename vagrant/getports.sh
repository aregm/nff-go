#!/bin/bash

if (( "$#" != 1 ))
then
    echo Usage: \$\(./getports.sh \<port number\>\)
    echo Script generates \$sc0, \$sc1, etc variables if specified port is 22, and generates
    echo \$da0, \$da1, etc if specified port is 2375.
    echo If specified port is 2375, script also generates NFF_GO_HOSTS variable.
    echo
    echo If VM_TOTAL_NUMBER is set, it is used as a number of VMs, otherwise 2 is used.
    echo If VM_NAME is set, it is used as a VM name prefix, otherwise default \"nff-go\" is used.
    exit 2
fi

port_number=$1

if [ -z "${VM_NAME}" ]
then
    vm_prefix=nff-go-
else
    vm_prefix=${VM_NAME}-
fi

if [ -z "${VM_TOTAL_NUMBER}" ]
then
    number=3
else
    number=${VM_TOTAL_NUMBER}
fi

if [ "${port_number}" == 22 ]
then
   pp="sc"
   vagrant ssh-config > $(pwd)/config.ssh
   for (( i=0; i<${number}; i++ ))
   do
       echo export ${pp}${i}=$(pwd)/config.ssh
   done
elif [ "${port_number}" == 2375 ]
then
    hosts=""
    np_hosts=""
    pp="da"
    status=$(vagrant status)
    for (( i=0; i<${number}; i++ ))
    do
        vm_name=${vm_prefix}${i}
        if echo "${status}" | grep ${vm_name} | grep -q libvirt
        then
            config=$(vagrant ssh-config ${vm_name})
            address=$(echo "${config}" | grep HostName | cut -d " " -f 4)
            port=${port_number}
        elif echo "${status}" | grep ${vm_name} | grep -q virtualbox
        then
            address=localhost
            port=$(vagrant port --guest ${port_number} ${vm_name})
        else
            echo Unknown provider for VM ${vm_name}
            break
        fi

        echo export ${pp}${i}=${address}:${port}
        if (( i==0 ))
        then
            hosts=${address}:${port}
            np_hosts=${address}
        else
            hosts=${hosts},${address}:${port}
            np_hosts=${np_hosts},${address}
        fi
    done
else
    echo Unknown port specified ${port_number}
    exit 1
fi

if [ "${port_number}" == 2375 ]
then
    echo export NFF_GO_HOSTS=${hosts}
    echo export no_proxy=${np_hosts}
fi
