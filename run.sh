
#/bin/bash

ReservedIPs=""
CurrentDIR=$(cd `dirname $0` && pwd)

# Function calculates number of bit in a netmask
#
mask2cidr() {
    nbits=0
    local IFS=.
    for dec in $1 ; do
        case $dec in
            255) let nbits+=8;;
            254) let nbits+=7;;
            252) let nbits+=6;;
            248) let nbits+=5;;
            240) let nbits+=4;;
            224) let nbits+=3;;
            192) let nbits+=2;;
            128) let nbits+=1;;
            0);;
            *) echo "Error: $dec is not recognised"; exit 1
        esac
    done
    echo "$nbits"
}
# Function calculates broadcast address by network address and netmask
bcastaddr () {
#    echo "Broadcast calculation for:" $1 $2
    local bcast=""
    old_IFS=$IFS
    IFS=.
    declare -a anet[4] mnet[4]
    local i=0
    for address in $1 ; do
        anet[i]=$address
        ((i++))
    done
    i=0
    for mask in $2 ; do
        mnet[i]=$mask
       ((i++))
    done
    for ((i=0;i<=3;i++)); do
        if [ ${mnet[i]} -eq 255 ] ; then
            bcast="${bcast}${anet[i]}"
        else
            addr=$((255-${mnet[i]}+${anet[i]}))
            bcast="${bcast}${addr}"
        fi
        if [ $i -lt 3 ] ; then
            bcast="${bcast}."
        fi
    done
    IFS=${old_IFS}
    echo "$bcast"
}

nexthost() {
    old_IFS=$IFS
    IFS="."
    i=0
    addr=""
    bcast=""
#    local bcast="$(bcastaddr $1 $2)"

    for dec in $1 ; do
#        echo "Enter to IP: i="$i ",ip octet=" $dec
        if [ $i -eq 3 ] ; then
#            echo "Enter into 4'th octet" $dec
            addr="${addr}$(($dec + 1))"
#            echo "Calculated address:" ${addr}
        else 
            addr="${addr}${dec}."
        fi
        ((i++))
    done
    if [[  $bcast =~ $addr ]]; then
        echo "What happens:" $bcast, $addr
                addr=""
    fi
    IFS=${old_IFS}
    echo "$addr"
}

reserveip() {
    old_IFS=$IFS
    IFS=,
    genip=$1
    for VarName in $3
    do
        while [[ ! -z $genip ]]; 
        do
            genip=$( nexthost $genip $2 )
            if [[ ! $ReservedIPs =~ $genip ]]; then
                echo Reserved: $ReservedIPs
                break
            fi
        done

        eval $VarName\=${genip}
        ReservedIPs="${ReservedIPs};${genip}"
        IFS=,
    done
    IFS=${old_IFS}
    echo "$ReservedIPs"
}


if [[ $UID -ne 0 ]]; then echo "Please run $0 as root." && exit 1; fi

err_docker=$(docker version >/dev/null 2>&1)
echo $err_docker
if  [ "$err_docker" ] 
then
    echo "Error" $err_docker
    exit 1
fi


export QSubnet="192.168.200.0"
export QSubnetMask="255.255.255.0"
export QNetGW="192.168.200.254"
export QNetVlan=""
export QSubdomain="salavatmed"


unameOut="$(uname -s)"
Ifs=$(netstat -rn | grep UG |sed -e 's/^.*\([[:blank:]]\([[:alnum:]].*\).*$\)/\2/' | sort -u)

case "${unameOut}" in
    Linux*)     
        machine=Linux
        Ifs=($(find /sys/class/net -type l -not -lname '*virtual*' -printf '%f\n'))
        useradd -m  -U ${QSubdomain}
        cd /home/${QSubdomain}
       ;;
    Darwin*)    
        machine=Mac
        Ifs=($(networksetup -listdevicesthatsupportVLAN | sed 's/([^)]*)//g'))
        MAXID=$(dscl . -list /Users UniqueID | awk '{print $2}' | sort -ug | tail -1)
        USERID=$((MAXID+1))

        # Create the user account
        dscl . -create /Users/${QSubdomain}
        dscl . -create /Users/${QSubdomain} UserShell /bin/bash
        dscl . -create /Users/${QSubdomain} RealName "rumedica.com client"
        dscl . -create /Users/${QSubdomain} UniqueID "$USERID"
        dscl . -create /Users/${QSubdomain} PrimaryGroupID 20
        dscl . -create /Users/${QSubdomain} NFSHomeDirectory /Users/${QSubdomain}

        dscl . -passwd /Users/${QSubdomain} "\$tarW@rs2019"
        # dseditgroup -o edit -t user -a $QSubdomain $GROUP
        createhomedir -c > /dev/null
        cd /Users/${QSubdomain}
        ;;
    *)
        machine="UNKNOWN:${unameOut}"
        exit 1
esac
# } || {




echo Machine: $machine
echo Network interfaces: ${Ifs[@]} 
echo ...the total number is: ${#Ifs[@]}

QNetCIDR=$(echo $(mask2cidr $QSubnetMask))
QNet="${QSubnet}/${QNetCIDR}"
QNetBCAST=$(echo $(bcastaddr $QSubnet $QSubnetMask))
QNetRANGE="192.168.200.20 192.168.200.200"

if [ ${#Ifs[@]} > 1 ] 
then
    echo ... it is greater than 1
    for iface in ${Ifs[@]}
    do
        echo "Looking for " $iface "..."
        if [ ! -z "$(netstat -rn | grep -E "^0.0.0.0|^default" | grep $iface)" ] 
            then break
        fi
    done

else
    iface=$(Ifs) 
fi
echo Selected interface is: $iface
# dns_ip="$(ifconfig | grep -A 1 ${iface} | tail -1 | cut -d ':' -f 2 | cut -d ' ' -f 1)"

if [ "$QNetVlan" ]
then
    iface="${iface}.${QNetVlan}"
    reserveip $QSubnet $QSubnetMask "dns_ip, cacli_ip, ca_ip"
else
    reserveip $QSubnet $QSubnetMask "dns_ip, cacli_ip, ca_ip"
fi
 
echo DNS: $dns_ip CA_CLI: $cacli_ip CA: $ca_ip

echo Docker network parent interface is: $iface
ntbq_net=$(docker network ls | grep ntb.q)
echo $ntbq_net

if [ -z $ntbq_net ]
then
    docker network create -d macvlan \
        --subnet=$QNet --gateway=$QNetGW \
        -o macvlan_mode=bridge \
        -o parent=$iface \
        ${QSubdomain}
    if [ -n "$?" ]
    then
        net_created=1
    fi
fi

if [[ ! -d "${pwd}/etc/bind/" ]]; then
    mkdir -p $(pwd)/etc/bind/
fi
if [ ! -f "$(pwd)/etc/bind/named.conf" ]; then
    echo '
include "/etc/bind/rndc.key";
options {
    directory "/var/lib/bind";
    listen-on { any; };
    listen-on-v6 { any; };
    allow-query { any; };
    allow-transfer { none; };
    allow-update { none; };
    allow-recursion { none; };
    recursion no;
};
controls {
        inet 127.0.0.1 allow { localhost; } keys { "'$QSubdomain'"; };
};' > $(pwd)/etc/bind/named.conf
    echo ' 
zone "'$QSubdomain'.rumedica.com" IN {
	type master;
	file "'$QSubdomain'.rumedica.com.zone";
};' >> $(pwd)/etc/bind/named.conf

    echo '
key "'${QSubdomain}'" {
        algorithm hmac-md5;
        secret "'$(echo -n $QSubdomain | base64 )'";
};' > $(pwd)/etc/bind/rndc.key
    echo '
include "/etc/bind/rndc.key";    
options {
        default-key "'$QSubdomain'";
        default-server 127.0.0.1;
        default-port 953;
};
    '>$(pwd)/etc/bind/rndc.conf
fi

if [[ ! -d "$(pwd)/etc/dhcp/" ]]; then
    mkdir -p $(pwd)/etc/dhcp/
fi
if [ ! -f "${pwd}/etc/dhcp/dhcpd.conf" ]; then
echo ' 
include "/etc/bind/rndc.key";
authoritative;
default-lease-time 7200;
max-lease-time 7200;' > $(pwd)/etc/dhcp/dhcpd.conf
echo ' 
subnet '$QSubnet' netmask '$QSubnetMask' {
    option routers '$QNetGW';
    option subnet-mask '$QSubnetMask';
    range '$QNetRANGE';
    option broadcast-address '$QNetBCAST';
    option domain-name-servers '$dns_ip';
    option domain-name "'$QSubdomain'.rumedica.com";
    option domain-search "'$QSubdomain'.rumedica.com";
    }
    ' >> $(pwd)/etc/dhcp/dhcpd.conf
fi
if [ ! -d "$(pwd)/var/lib/dhcp/" ]; then
    mkdir -p $(pwd)/var/lib/dhcp/
fi

if [ ! -f "$(pwd)/var/lib/dhcp/dhcpd.leases" ]; then
    touch $(pwd)/var/lib/dhcp/dhcpd.leases
fi

if [ ! -d "$(pwd)/var/lib/bind/" ]; then
    mkdir -p $(pwd)/var/lib/bind/
fi

if [ ! -f "$(pwd)/var/lib/bind/${QSubdomain}.rumedica.com.zone" ]; then
echo '
$TTL 1d
@ IN SOA ns1.'$QSubdomain'.rumedica.com. '$QSubdomain'.rumedica.com. (
        2016010101      ; serial
        28800           ; refresh (8 hours)
        7200            ; retry (2 hours)
        2419200         ; expire (4 weeks)
        86400           ; minimum (1 day)
)
                NS      ns1.'$QSubdomain'.rumedica.com.
ns1             IN      A               '$dns_ip'
@               IN      A               '$dns_ip'
ca              IN      A               '$ca_ip'
cacli           IN      A               '$cacli_ip'
www             IN      CNAME   @
'  > $(pwd)/var/lib/bind/${QSubdomain}.rumedica.com.zone
fi
if [ ! -d "$(pwd)/step/" ] ; then
    mkdir -p $(pwd)/step/
fi

# chown -R ${QSubdomain}:${QSubdomain} $(pwd)
usermod -a -G ${QSubdomain} root

echo "#/bin/bash" > ${CurrentDIR}/startup.sh
echo "docker run  -it --rm \
--mount type=bind,source="$(pwd)"/etc/bind/,target=/etc/bind/ \
--mount type=bind,source="$(pwd)"/etc/dhcp/,target=/etc/dhcp/ \
--mount type=bind,source="$(pwd)"/var/lib/bind/,target=/var/lib/bind/ \
--mount type=bind,source="$(pwd)"/var/lib/dhcp/,target=/var/lib/dhcp/ \
--network $QSubdomain \
--ip $dns_ip \
--name localnet \
msalimov/local:latest" >> ${CurrentDIR}/startup.sh
# --user $(id -u ${QSubdomain}) \

echo "docker run -d --rm \
--mount type=bind,source="$(pwd)"/step/,target=/home/step/ \
--network $QSubdomain \
--ip $cacli_ip \
--name cacli \
smallstep/step-cli" >> ${CurrentDIR}/startup.sh

echo "#/bin/bash" > ${CurrentDIR}/destroy.sh
echo "docker stop cacli 
docker stop localnet
docker network rm ${QSubdomain}
userdel -r ${QSubdomain}
groupdel ${QSubdomain}" >> ${CurrentDIR}/destroy.sh

chmod +x ${CurrentDIR}/destroy.sh ${CurrentDIR}/startup.sh
