
#!/bin/bash

ReservedIPs=""
CurrentDIR=$(cd `dirname $0` && pwd)
function valid_ip()
{
    local  ip=$1
    local  stat=1

    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($ip)
        IFS=$OIFS
        [[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}
# CalcQNet $DefaultGateway $DefaultNetmask "QSubnet, QSubnetMask, QNetCIDR, QNetBCAST, QNetARPA"

CalcQNet() {
    declare -a netaddress[4] netmask[4] netbroadcast[4] result[6]
    local netcidr=0
    local netarpa="in-addr.arpa.net"
    local i=0
    old_IFS=$IFS
    IFS=.
    for a in $1 ; do
        netaddress[i]=$a
        ((i++))
    done
    i=0
    j=0
    for m in $2 ; do
        case $m in
            255) let netcidr+=8;;
            254) let netcidr+=7;;
            252) let netcidr+=6;;
            248) let netcidr+=5;;
            240) let netcidr+=4;;
            224) let netcidr+=3;;
            192) let netcidr+=2;;
            128) let netcidr+=1;;
            0);;
            *) echo "Exit 1"; exit 1
        esac
        if [ $m -lt 255 ]; then
            ((j++))
            if [ $j -gt 2 ] ; then

                echo "Exit 2"
                exit 1
            fi
        fi
        netmask[i]=$m
        netaddress[i]=$((netaddress[i]&netmask[i]))
        notmask=255-$m
        netbroadcast[i]=$((netaddress[i]|notmask))
        if [ ${netaddress[i]} -gt 0 ]
        then
            netarpa="${netaddress[i]}.${netarpa}"
        fi
        ((i++))
    done
    IFS=,
    result[0]=${netaddress[@]}
    result[0]=${result[0]//' '/\.}
    result[1]=${netmask[@]}
    result[1]=${result[1]//' '/\.}
    result[2]=${netcidr}
    result[3]=${netbroadcast[@]}
    result[3]=${result[0]//' '/\.}
    result[4]=${netarpa}
    result[5]="192.168.200.20 - 192.168.200.30"
    i=0
    for VarName in $3; do
        echo $VarName=${result[i]}
        eval $VarName\=${result[i]}
        ((i++))
    done
    IFS=${old_IFS}
}
# Function nexthost() calculate next ip address from base
# base ip address and network mask are comes in parameters
# Parameters:
# $1 - base IP address from wich next ip will calculated
# $2 - network mask
# ip-addresses in format A.B.C.D
nexthost() {
    local i=0
    local ipsum=0
    local nexthost=0
    local maxhost=0
    local result=""
    declare -a address[4] mask[4] net[4]
    old_IFS=$IFS
    IFS="."
    for octet in $1 ; do
        address[i]=$octet
        ((i++))
    done
    i=0; ipsum=0; maxhost=0
    for octet in $2; do
        mask[i]=$((255-$octet))
        net[i]=$((address[i]^mask[i]))
        shiftindex=$((3-i))
        ipsum=$((mask[i]<<shiftindex))
        maxhost=$((maxhost|ipsum))

        ((i++))
    done
    echo Mask: mask[@], Net: net[@]
    ipsum=0;
    for ((i=0; i<=3; i++))
    do
        ipsum=$((address[i]&mask[i]))
        shiftindex=$((3-i))
        shiftindex=$((shiftindex*8))
        ipsum=$((ipsum<<shiftindex))
        nexthost=$((nexthost|ipsum))
    done
    nexthost=$((nexthost+1))
    IFS=${old_IFS}
    if [ $nexthost -lt $maxhost ] ; then echo ""
    else
        ipsum=0
        for ((i=0; i<=3; i++))
        do
            shiftindex=$((3-i))
            shiftindex=$((shiftindex*8))
            nexthost=$((nexthost^ipsum))
            ipsum=$((nexthost>>shiftindex))
            octet=$((ipsum|net[i]))
            ipsum=$((ipsum<<shiftindex))
            result="$result.$octet"
            echo CalculatedIP:$result
        done
    fi
    echo "$result"
}

reserveip() {
    old_IFS=$IFS
    local genip=$1
    local netmask=$2
    IFS=,
    for VarName in $3
    do
        while [[ ! -z $genip ]]; 
        do
            genip=$( nexthost $genip $netmask )
            if [[ ! $ReservedIPs =~ $genip ]]; then
                break
            fi
        done

        eval $VarName\=${genip}
        ReservedIPs="${ReservedIPs};${genip}"
        IFS=,
    done
    IFS=${old_IFS}
}


if [[ $UID -ne 0 ]]; then echo "Please run $0 as root." && exit 1; fi

err_docker=$(docker version >/dev/null 2>&1)
echo $err_docker
if  [ "$err_docker" ] 
then
    echo "Error" $err_docker
    exit 1
fi

export QSubdomain="salavatmed"

unameOut="$(uname -s)"
# Ifs=$(netstat -rn | grep UG |sed -e 's/^.*\([[:blank:]]\([[:alnum:]].*\).*$\)/\2/' | sort -u)
# ip route get 1 | sed 's/^.*src \([^ ]*\).*$/\1/;q'

case "${unameOut}" in
    Linux*)     
        machine=Linux
        Ifs=($(find /sys/class/net -type l -not -lname '*virtual*' -printf '%f\n'))
        DefaultIP=$(ping -c 1 -n $(hostname) | head -1 | cut -d' ' -f3)
        DefaultIP=${DefaultIP#*\(}
        DefaultIP=${DefaultIP%\)*}
        DefaultRoute=$(cat /proc/net/route | head -2 | tail -1)
        DefaultInterface=$(echo $DefaultRoute | cut -d' ' -f1)
        RouteTable=$(cat /proc/net/route | grep ${DefaultInterface}.*0001.*)
        DefaultGateway=$(echo $DefaultRoute | cut -d' ' -f3)
        DefaultNetwork=$(echo $RouteTable | cut -d' ' -f2)
        DefaultNetmask=$(echo $RouteTable | cut -d' ' -f8)
        DefaultNetwork=$(printf "%d." $(echo $DefaultNetwork | sed 's/../0x& /g' | tr ' ' '\n' | tac) | sed 's/\.$/\n/')
        DefaultGateway=$(printf "%d." $(echo $DefaultGateway | sed 's/../0x& /g' | tr ' ' '\n' | tac) | sed 's/\.$/\n/')
        DefaultNetmask=$(printf "%d." $(echo $DefaultNetmask | sed 's/../0x& /g' | tr ' ' '\n' | tac) | sed 's/\.$/\n/')
        useradd -m  -U ${QSubdomain}
        cd /home/${QSubdomain}
       ;;
    Darwin*)    
        machine=Mac
        Ifs=($(networksetup -listdevicesthatsupportVLAN | sed 's/([^)]*)//g'))
        DefaultRoute=$(netstat -rn -f inet | grep -E "^0.0.0.0|^default")
        DefaultGateway=$(echo $DefaultRoute | awk '{print $2}')
        DefaultInterface=$(echo $DefaultRoute | awk '{print $4}')
        DefaultIP=$(ifconfig ${DefaultInterface} | grep inet | cut -d' ' -f2)
        DefaultNetmask=$(ifconfig ${DefaultInterface} | grep inet | cut -d' ' -f4)
        DefaultNetmask=$(printf "%d." $(echo $DefaultNetmask | sed 's/0x//g' | sed 's/../0x& /g') | sed 's/\.$//')
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

if [ ${#Ifs[@]} > 1 ] 
then
    echo ... it is greater than 1
    for iface in ${Ifs[@]}
    do
        echo "Looking for " $iface "..."
        tmpStr=${DefaultRoute#*${iface}}
        if [ ${#tmpStr} -lt ${#DefaultRoute} ] 
            then break
        fi
    done

else
    iface=$(Ifs) 
fi
echo Selected interface is: $iface

# Network address, 192.168.1.0/24: QSubnet=192.168.1.0
QSubnet="192.168.200.0"
# Network subnet mask "255.255.255.0"
QSubnetMask="255.255.255.0"
# NNetwork Default Gateway address
QNetGW="192.168.200.254"
# Network CIDR 255.255.255.0=>/24
QNetCIDR=24
# Network in CIDR format 192.168.1.0/24
# QNet=
# Network broadcast address 192.168.1.0/24: QNetBCAST=192.168.1.255
QNetBCAST="192.168.200.255"
# DHCP address pool
QNetRANGE="192.168.200.20 192.168.200.200"
# IP address in ARPA format 127.0.0.1=>0.0.127.IN-ADDR.ARPA.NET
QNetARPA="200.168.192.in-addr.arpa.net" 

# VLAN subinterface used
QNetVlan=""
if [ $QNetVlan ] ;
then
    # Do calculate network parameters
    echo SubVLAN interface defined
    iface="${iface}.${QNetVlan}"
else
    echo No SubVLAN interface
    QNetGW=${DefaultGateway}
fi
CalcQNet $DefaultGateway $DefaultNetmask "QSubnet, QSubnetMask, QNetCIDR, QNetBCAST, QNetARPA, QNetRANGE"

reserveip $QSubnet $QSubnetMask "dns_ip, cacli_ip, ca_ip"

echo Docker network parent interface is: $iface
ntbq_net=$(docker network ls | grep ntb.q)
echo $ntbq_net

if [ -z $ntbq_net ]
then    
    docker network create -d macvlan \
        --subnet="${QSubnet}/${QNetCIDR}" --gateway=$QNetGW \
        -o macvlan_mode=bridge \
        -o parent=$iface \
        ${QSubdomain}
    if [ -z "$?" ]
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
};
forwarders {
    8.8.8.8;
    8.8.4.4;
};
' > $(pwd)/etc/bind/named.conf
    echo ' 
zone "'$QSubdomain'.rumedica.com" IN {
	type master;
    allow-update { key '$QSubdomain'; };
	file "'$QSubdomain'.rumedica.com.zone";
};
zone "${QNetARPA}" IN {
    type master;
    allow-update { key '$QSubdomain'; };
    file "${QNetARPA}";
}    
' >> $(pwd)/etc/bind/named.conf

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
ddns-updates on;
update-static-leases on;
ddns-domainname "'$QSubdomain'.rumedica.com";
ddns-update-style interim;
ignore client-updates;
update-static-leases true;
default-lease-time 7200;
max-lease-time 7200;
local-address '$dns_ip';
zone '$QSubdomain'.rumedica.com. { primary '$dns_ip'; key '$QSubdomain'; }
zone '$QNetARPA'. { primary '$dns_ip'; key '$QSubdomain'; }
' > $(pwd)/etc/dhcp/dhcpd.conf
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
if [ ! -f "$(pwd)/var/lib/bind/${QNetARPA}" ]; then
echo '
$TTL 1d     ; 1 week
@  IN  SOA    ns1.'$QSubdomain'.rumedica.com. '$QSubdomain'.rumedica.com. (
        2016010101      ; serial
        28800           ; refresh (8 hours)
        7200            ; retry (2 hours)
        2419200         ; expire (4 weeks)
        86400           ; minimum (1 day)
                                )
@		        IN	    NS	               ns1.'$QSubdomain'.rumedica.com.
${dns_ip##*.}	IN	    PTR                ns1.'$QSubdomain'.rumedica.com.
${ca_ip##*.}    IN      PTR                ca.${QSubdomain}.rumedica.com.
${cacli_ip##*.} IN      PTR                cacli.${QSubdomain}.rumedica.com.
' > $(pwd)/var/lib/bind/${QNetARPA}.zone
fi
if [ ! -d "$(pwd)/step/" ] ; then
    mkdir -p $(pwd)/step/
fi

chown -R ${QSubdomain}:${QSubdomain} $(pwd)
usermod -a -G ${QSubdomain} root

echo "#/bin/bash" > ${CurrentDIR}/startup.sh
echo "docker run  -it --rm \
--mount type=bind,source="$(pwd)"/etc/bind/,target=/etc/bind/ \
--mount type=bind,source="$(pwd)"/etc/dhcp/,target=/etc/dhcp/ \
--mount type=bind,source="$(pwd)"/var/lib/bind/,target=/var/lib/bind/ \
--mount type=bind,source="$(pwd)"/var/lib/dhcp/,target=/var/lib/dhcp/ \
--user $(id -u ${QSubdomain}) \
--network $QSubdomain \
--ip $dns_ip \
--name localnet \
msalimov/local:latest" >> ${CurrentDIR}/startup.sh


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
