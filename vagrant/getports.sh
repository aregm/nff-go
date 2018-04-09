#!/bin/bash

if (( "$#" != 1 ))
then
    echo Usage: \$\(./getports.sh \<port number\>\)
    echo Script generates \$sp0, \$sp1, etc variables if specified port is 22, and generates
    echo \$dp0, \$dp1, etc if specified port is 2375.
    echo If specified port is 2375, script also generates NFF_GO_HOSTS variable.
    echo
    echo If VM_TOTAL_NUMBER is set, it is used as a number of VMs, otherwise 2 is used.
    echo If VM_NAME is set, it is used as a VM name prefix, otherwise default \"nff-go\" is used.
    exit 2
fi

port_number=$1

if [ "${port_number}" == 22 ]
then
   pp="sp"
elif [ "${port_number}" == 2375 ]
then
    hosts=""
    pp="dp"
else
    echo Unknown port specified ${port_number}
    exit 1
fi

if [ -z "${VM_NAME}" ]
then
    vm_prefix=nff-go-
else
    vm_prefix=${VM_NAME}-
fi

if [ -z "${VM_TOTAL_NUMBER}" ]
then
    number=2
else
    number=${VM_TOTAL_NUMBER}
fi

for (( i=0; i<${number}; i++ ))
do
    port=$(vagrant port --guest ${port_number} ${vm_prefix}${i})
    echo export ${pp}${i}=${port}
    if [ "${port_number}" == 2375 ]
    then
        if (( i>0 ))
        then
            hosts=${hosts},
        fi
        hosts=${hosts}localhost:${port}
    fi
done

if [ "${port_number}" == 2375 ]
then
    echo export NFF_GO_HOSTS=${hosts}
fi
