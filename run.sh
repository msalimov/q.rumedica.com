
#/bin/bash

export QSubnet="192.168.200.0"
export QSubnetMask="255.255.255.0"
export QNetGW="192.168.200.254"
export QNetVlan="200"
export QSubdomain="salavatmed"

ReservedIPs=""

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
#    echo "Nexthost input 1:" $1 $2 "IFS:" ${IFS}
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

# echo "Nexthost test..."
# newip=$( nexthost $QSubnet $QSubnetMask )
# echo "given ip :" $newip

reserveip $QSubnet $QSubnetMask "dns_ip, cacli_ip, ca_ip" 
echo DNS: $dns_ip CA_CLI: $cacli_ip CA: $ca_ip

QNetCIDR=$(echo $(mask2cidr $QSubnetMask))
QNet="${QSubnet}/${QNetCIDR}"
QNetBCAST=$(echo $(bcastaddr $QSubnet $QSubnetMask))



err_docker=$(docker version >/dev/null 2>&1)
echo $err_docker
if  [ "$err_docker" ] 
then
    echo "Error" $err_docker
    exit 1
fi

unameOut="$(uname -s)"
Ifs=$(netstat -rn | grep UG |sed -e 's/^.*\([[:blank:]]\([[:alnum:]].*\).*$\)/\2/' | sort -u)
case "${unameOut}" in
    Linux*)     
        machine=Linux
        Ifs=($(find /sys/class/net -type l -not -lname '*virtual*' -printf '%f\n'))
       ;;
    Darwin*)    
        machine=Mac
        Ifs=($(networksetup -listdevicesthatsupportVLAN | sed 's/([^)]*)//g'))
        ;;
    *)
        machine="UNKNOWN:${unameOut}"
        exit 1
esac

echo Machine: $machine
echo Network interfaces: ${Ifs[@]} 
echo ...the total number is: ${#Ifs[@]}

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

if [ "$QNetVlan" ]
then
    iface="${iface}.${QNetVlan}"
fi

echo Docker network parent interface is: $iface
ntbq_net=$(docker network ls | grep ntb.q)
echo $ntbq_net

if [ -n $ntbq_net ]
then
    docker network create -d macvlan \
        --subnet=$QNet --gateway=$QNetGW \
        -o parent=$iface \
        ntb.q
    if [ -n "$?" ]
    then
        net_created=1
    fi
fi

if [ ! -d "${pwd}/etc/bind/" ]; then
    mkdir -p $(pwd)/etc/bind/
fi
if [ ! -f "$(pwd)/etc/bind/named.conf" ]; then
    echo '
    options {
        directory "/var/lib/bind";
        listen-on { any; };
        listen-on-v6 { any; };
        allow-query { any; };
        allow-transfer { none; };
        allow-update { none; };
        allow-recursion { none; };
        recursion no;
    };' > $(pwd)/etc/bind/named.conf
    echo ' 
    zone "'$QSubdomain'.rumedica.com" IN {
	    type master;
	    file "'$QSubdomain'.rumedica.com.zone";
    };' >> $(pwd)/etc/bind/named.conf
fi

if [ ! -d "${pwd}/etc/dhcp/" ]; then
    mkdir -p $(pwd)/etc/dhcp/
fi
if [ ! -f "${pwd}/etc/dhcp/dhcpd.conf" ]; then
    echo ' 
    authoritative;
    default-lease-time 7200;
    max-lease-time 7200;' > $(pwd)/etc/dhcp/dhcpd.conf
    echo ' 
    subnet '$QSubnet' netmask '$SubnetMask' {
        option routers '$QNetGW';
        option subnet-mask '$QSubnetMask';
        range '$QNetRANGE';
        option broadcast-address '$QNetBCAST';
        option domain-name-servers '$dns_ip';
        option domain-name "'$QSubdomain'.rumedica.com";
        option domain-search "'$QSubdomain'.rumedica.com";
    ' >> $(pwd)/etc/dhcp/dhcpd.conf
fi
if [ ! -d "${pwd}/var/lib/bind/" ]; then
    mkdir -p $(pwd)/var/lib/bind/
fi
if [ ! -f "${pwd}/var/lib/bind/${QSubdomain}.rumedica.com.zone" ]; then
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

docker run  -it --rm \
--mount type=bind,source="$(pwd)/etc/bind/",target=/etc/bind/ \
--mount type=bind,source="$(pwd)/etc/dhcp/",target=/etc/dhcp/ \
--mount type=bind,source="$(pwd)/var/lib/bind/",target=/var/lib/bind/ \
--network "ntb.q" \
--ip $dns_ip \
msalimov/local:latest

