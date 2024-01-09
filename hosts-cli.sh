#! /bin/bash

cd "$(dirname "$(readlink -f $0)")"

FILE=/etc/hosts
BACKUPF=/tmp/hosts
TMPF=/tmp/hosts.tmp

CMD=0
HELP=0
DOMAIN=0
GROUP=0
SUBS=0
ALL=0
IP=0

FQDN_RE='(?=.{4,253}$)((?:[a-zA-Z0-9](?:(?:[a-zA-Z0-9\-]){0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|xn--[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])$)'
IP_RE='\d+\.\d+\.\d+\.\d+'
GROUP_RE='\[[^\]]+\]'

declare -A GROUPS_DOMAINS
declare -A GROUPS_IPS
declare -a DNS_GROUPS
declare -a DISABLEDS

function show_help {
    echo -e "\e[1mhosts-cli\e[0m - CLI to handle /etc/hosts file as a local dns resolver"
    echo
    echo -e "\e[4mUsage\e[0m: dns [command] [options] domain"
    echo
    echo -e "\e[4mCommands\e[0m:"
    echo "  list, ls                       List available domains by state"
    echo "  add                            Add a domain or a group to the dns file"
    echo "  drop                           Drop domain or a group from the dns file"
    echo "  enable                         Enable a domain or a group from the dns file"
    echo "  disable                        Disable a domain or a group from the dns file"
    echo
    echo -e "\e[4mOptions\e[0m:"
    echo "  -h, --help                     Show help"
    echo "  -i, --ip                       Bind to IP"
    echo "  -s, --sub                      Target the domain and all its subdomains"
    echo "  -g, --group                    Domains group"
    exit
}

function parse_opts {
    IFS=' '; read -a args <<< "$@"

    opt=0
    val=0
    i=0
    for arg in "${args[@]}"; do
        if [ "$arg" = 'add' ] && [ $i -eq 0 ]; then
            CMD='add'
        elif [ "$arg" = 'drop' ] && [ $i -eq 0 ]; then
            CMD='drop'
        elif [ "$arg" = 'list' ] && [ $i -eq 0 ]; then
            CMD='list'
        elif [ "$arg" = 'ls' ] && [ $i -eq 0 ]; then
            CMD='list'
        elif [ "$arg" = 'list-domains' ] && [ $i -eq 0 ]; then
            CMD='list-domains'
        elif [ "$arg" = 'list-groups' ] && [ $i -eq 0 ]; then
            CMD='list-groups'
        elif [ "$arg" = 'enable' ] && [ $i -eq 0 ]; then
            CMD='enable'
        elif [ "$arg" = 'disable' ] && [ $i -eq 0 ]; then
            CMD='disable'
        elif [ "$arg" = '-i' ] || [ "$arg" = '--ip' ]; then
            opt='IP'
        elif [ "$arg" = '-d' ] || [ "$arg" = '--domain' ]; then
            opt='DOMAIN'
        elif [ "$arg" = '-g' ] || [ "$arg" = '--group' ]; then
            opt='GROUP'
        elif [ "$arg" = '-h' ] || [ "$arg" = '--help' ]; then
            HELP=1
        elif [ "$arg" = '-s' ] || [ "$arg" = '--sub' ]; then
            SUBS=1
        elif [ "$arg" = '-a' ] || [ "$arg" = '--all' ]; then
            ALL=1
        elif [ "$opt" = 'IP' ]; then
            if [ $(validate_ip $arg) -eq 0 ]; then
                echo -e "\e[31mError: Invalid IP: $arg\e[0m"
                show_help
            else
                IP=$arg
                opt=0
            fi
        elif [ "$opt" = 'DOMAIN' ]; then
            DOMAIN=$arg
            opt=0
        elif [ "$opt" = 'GROUP' ]; then
            GROUP=$arg
            opt=0
        elif [ -n "$CMD" ] && [ $((i+1)) -eq ${#args[@]} ]; then
            is_valid=$(validate_fqdn $arg)
            if [ $is_valid -eq 1 ]; then
                DOMAIN=$arg
            else
                echo -e "\e[31mError: Invalid domain name $arg\e[0m"
                show_help
            fi
        else
            echo -e "\e[31mError: Unkown option $arg\e[0m"
            show_help
        fi
        i=$((i+1))
    done
}

function validate_args {
    IFS=' '; read -a args <<< "$@"
    for arg in "${args[@]}"; do
        if [ "$arg" = 'domain' ] && [ "$(validate_fqdn $DOMAIN)" -eq 0 ]; then
            echo -e "\e[31mError: Invalid domain name: $DOMAIN\e[0m"
        elif [ "$arg" = 'ip' ] && [ $(validate_ip $IP) -eq 0 ]; then
            echo -e "\e[31mError: Invalid ip: $IP\e[0m"
        fi
    done
}

function validate_fqdn {
    match="$(echo $1 | grep -oP "$FQDN_RE")"
    if [ -n "$match" ]; then
        echo 1
    else
        echo 0
    fi
}

function validate_ip {
    match="$(echo $1 | grep -oP "$IP_RE")"
    if [ -n "$match" ]; then
        echo 1
    else
        echo 0
    fi
}

function get_leading {
    echo "$(echo $1 | grep -oP '^#?\s*')"
}

function list {
    if [ "$1" == '-d' ]; then
        echo "$(grep -oP "$FQDN_RE" $FILE | xargs)"
        exit
    elif [ "$1" == '-g' ]; then
        echo "$(grep -oP "$GROUP_RE" $FILE | grep -oP '[^\[\]]+' | xargs)"
        exit
    fi
    echo -e "\e[4mEnabled\e[0m"
    for match in $(cat $FILE | grep -P "^($IP_RE\s+$FQDN_RE|#\s*$GROUP_RE)"); do
        if [ "$GROUP" != '0' ]; then
            domain=$(echo "$match" | grep -Po "$FQDN_RE")
            test -z "$domain" && continue
            test -z "$(echo "${GROUPS_DOMAINS[$GROUP]}" | grep "$domain")" && continue
        fi
        if [ -n "$(echo "$match" | grep '^#')" ]; then
            leading="$(get_leading $match)"
            echo "$(echo "$match" | grep -Po "(?<=$leading).*")"
        else
            echo "$match"
        fi
    done
    echo
    echo -e "\e[4mDisabled\e[0m"
    for match in $(cat $FILE | grep -oP "(?<=^#)\s*($IP_RE\s+$FQDN_RE|$GROUP_RE)"); do
        if [ "$GROUP" != '0' ]; then
            domain=$(echo "$match" | grep -Po "$FQDN_RE")
            test -z "$domain" && continue
            test -z "$(echo "${GROUPS_DOMAINS[$GROUP]}" | grep "$domain")" && continue
        fi
        leading="$(get_leading $match)"
        echo "$(echo "$match" | grep -Po "(?<=$leading).*")"
    done
}

function it_exists {
    if [ "$1" == '-g' ]; then
        exists=$(grep -oP "$GROUP_RE" $FILE | grep -P "\[$2\]")
    else
        exists=$(grep -P "$FQDN_RE" $FILE | grep -P "\s$1$")
    fi

    if [ -n "$exists" ]; then
        echo 1
    else
        echo 0
    fi
}

function add_group {
    echo "# [$1]" | sudo tee -a $FILE >/dev/null 
}

function add {
    if [ "$GROUP" != '0' ] && [ "$DOMAIN" == '0' ]; then
        if [ $(it_exists -g $GROUP) -eq 0 ]; then
            add_group $GROUP
            echo -e "\e[1m$GROUP added as dns group\e[0m"
        else
            echo -e "\e[33mWarning: $GROUP is already on the dns file. Skip\e[0m"
        fi
    else
        if [ "$IP" = '0' ]; then
            IP='127.0.0.1'
        fi
        validate_args 'domain' 'ip'


        if [ $(it_exists $DOMAIN) -eq 0 ]; then
            if [ "$GROUP" == '0' ]; then
                GROUP='main'
                if [ $(it_exists -g $GROUP) -eq 0 ]; then
                    add_group $GROUP 
                    echo -e "\e[1m$GROUP added as dns group\e[0m"
                fi
            fi

            if [ $(it_exists -g $GROUP) -eq 1 ]; then
                drop_group $GROUP
                add_group $GROUP
                IFS=' '; read -a domains <<< ${GROUPS_DOMAINS[$GROUP]}
                IFS=' '; read -a host_ips <<< ${GROUPS_IPS[$GROUP]}
                i=0
                for domain in ${domains[@]}; do
                    ip=${host_ips[$i]}
                    if [ -z "$(echo ${DISABLEDS[@]} | grep "\s$domain")" ]; then
                        echo "$ip   $domain" | sudo tee -a $FILE >/dev/null
                    else
                        echo "# $ip   $domain" | sudo tee -a $FILE >/dev/null
                    fi
                    i=$((i+1))
                done
                echo "$IP   $DOMAIN" | sudo tee -a $FILE >/dev/null
                echo -e " \e[1m$DOMAIN\e[0m: added with IP $IP\e[0m"
            else
                echo -e "\e[33mWarning: Can't find $GROUP group on the dns file. Skip\e[0m"
            fi
        else
            echo -e "\e[33mWarning: $DOMAIN is already on the dns file. Skip\e[0m"
        fi
    fi
}

function drop_line {
    grep -v "\s$1$" $FILE | sudo tee $TMPF >/dev/null && cat $TMPF | sudo tee $FILE >/dev/null && sudo rm $TMPF >/dev/null
}

function drop_group {
    IFS=' '; read -a domains <<< ${GROUPS_DOMAINS[$1]}
    for domain in ${domains[@]}; do
        drop_line $domain
    done
    drop_line "\[$1\]"
}

function drop {
    if [ "$GROUP" != '0' ] && [ "$DOMAIN" == '0' ]; then
        if [ $(it_exists -g $GROUP) -eq 1 ]; then
            drop_group $GROUP
            echo -e " \e[1m$GROUP\e[0m: dropped"
        else
            echo -e "\e[33mWarning: Cant find $GROUP group on the dns file. Skip\e[0m"
        fi
    else
        validate_args 'domain'

        if [ $SUBS -gt 0 ]; then
            grep -P "$IP_RRE\s+\w+\.$DOMAIN$" $FILE | while read -r entry; do
                domain="$(echo $entry | grep -Po "$FQDN_RE")"
                drop_line $domain
                echo -e " \e[1m$domain\e[0m: dropped"
            done
        fi
        if [ $(it_exists $DOMAIN) -eq 1 ]; then
            drop_line $DOMAIN
            echo -e " \e[1m$DOMAIN\e[0m: dropped"
        else
            echo -e "\e[33mWarning: Cant find $DOMAIN on the dns file. Skip\e[0m"
        fi
    fi
}

function enable_domain {
    ip=$1
    domain=$2
    sudo sed -i -E "s/#\s*$ip\s+$domain/$ip $domain/g" $FILE
}

function enable {
    if [ "$GROUP" != '0' ] && [ "$DOMAIN" == '0' ]; then
        if [ $(it_exists -g $GROUP) -eq 1 ]; then
            IFS=' '; read -a domains <<< ${GROUPS_DOMAINS[$GROUP]}
            IFS=' '; read -a ips <<< ${GROUPS_IPS[$GROUP]}
            i=0
            for domain in ${domains[@]}; do
                ip=${ips[$i]}
                enable_domain $ip $domain
                i=$((i+1))
            done
            echo -e " \e[1m$GROUP\e[0m: enabled"
        else
            echo -e "\e[33mWarning: Can't find $GROUP group on the dns file. Skip\e[0m"
        fi
    else
        validate_args 'domain'

        domain=$DOMAIN
        regexp="^#\s*$IP_RE\s+$domain$"
        if [ $SUBS -gt 0 ]; then
            # domain="${domain#*.}"
            regexp="^#\s*$IP_RE.*$domain$"
        fi

        match="$(grep -P "$regexp" $FILE)"
        if [ -n "$match" ]; then
            grep -P "$regexp" $FILE | while read -r entry; do
                ip="$(echo $entry | grep -Po "$IP_RE")"
                domain="$(echo $entry | grep -Po "$FQDN_RE$")"
                enable_domain $ip $domain
                echo -e " \e[1m$domain\e[0m: enabled"
            done
        else
            echo -e "\e[31mError: No matching domain for $domain\e[0m"
            exit
        fi
    fi
}

function disable_domain {
    ip=$1
    domain=$2
    sudo sed -i -E "s/^$ip\s+$domain/# $ip  $domain/g" "$FILE"
}

function disable {
    if [ "$GROUP" != '0' ] && [ "$DOMAIN" == '0' ]; then
        if [ $(it_exists -g $GROUP) -eq 1 ]; then
            IFS=' '; read -a domains <<< ${GROUPS_DOMAINS[$GROUP]}
            IFS=' '; read -a ips <<< ${GROUPS_IPS[$GROUP]}
            i=0
            for domain in ${domains[@]}; do
                ip=${ips[$i]}
                disable_domain $ip $domain
                i=$((i+1))
            done
            echo -e " \e[1m$GROUP\e[0m: disabled"
        else
            echo -e "\e[33Warning: Can't find $GROUP group on the dns file. Skip\e[0m"   
        fi
    else
        validate_args 'domain'

        if [ $(it_exists $DOMAIN) -eq 1 ]; then
            domain=$DOMAIN
            regexp="^$IP_RE\s+$domain"
            if [ $SUBS -gt 0 ]; then
                # domain="${domain#*.}"
                regexp="^$IP_RE.*$domain"
            fi

            match="$(grep -P "$regexp" $FILE)"
            if [ -n "$match" ]; then
                grep -P "$regexp" $FILE | while read -r entry; do
                    ip="$(echo $entry | grep -Po "$IP_RE")"
                    domain="$(echo $entry | grep -Po '\s.*$' | grep -Po "$FQDN_RE")"
                    disable_domain $ip $domain
                    echo -e " \e[1m$domain\e[0m: disabled"
                done
            else
                echo -e "\e[31mError: No matching domain for $domain\e[0m"
            fi
        else
            echo -e "\e[33Warning: Can't fins $DOMAIN domain on the dns file. Skip\e[0m"
        fi
    fi
}

function parse_groups {
    IFS=,$'\n'; read -d '' -r -a hosts < /etc/hosts
    declare -a childs
    declare -a ips
    current="MAIN"
    gi=0
    ci=0
    di=0
    for line in ${hosts[@]}; do
        is_group=$(echo $line | grep -P "$GROUP_RE")
        if [ -n "$is_group" ]; then
            gi=$((${#DNS_GROUPS[@]}+1))
            DNS_GROUPS[$gi]=$current
            GROUPS_DOMAINS[$current]=${childs[@]}
            GROUPS_IPS[$current]=${ips[@]}
            current=$(echo $line | grep -oP "$GROUP_RE" | grep -oP '[^\[|\]]+')
            childs=()
            ips=()
            ci=0
        else
            ip=$(echo $line | grep -Po "$IP_RE")
            domain=$(echo $line | grep -Po "$IP_RE\s+.*$" | grep -Po "$FQDN_RE$")
            if [ -n "$domain" ]; then
                is_disabled="$(test -n "$(echo $line | grep -P '^#')" && echo 1 || echo 0)"
                if [ $is_disabled -eq 1 ]; then
                    DISABLEDS[$di]=$domain
                    di=$((di+1))
                fi
                childs[$ci]="$domain"
                ips[$ci]="$ip"
                ci=$((ci+1))
            fi
        fi
    done
    gi=$((gi+1))
    DNS_GROUPS[$gi]=$current
    GROUPS_DOMAINS[$current]=${childs[@]}
    GROUPS_IPS[$current]=${ips[@]}
}

function backup {
    sudo cp $FILE $BACKUPF
}

function restore {
    if [ -f $BACKUPF ]; then
        cat $BACKUPF | sudo tee $FILE >/dev/null
    else
        echo -e "\e[31m\e[1mError: No backup file\e[0m\e[0m"
    fi
}

parse_opts $@
parse_groups

if [ $HELP -gt 0 ] || [ "$CMD" = '0' ]; then
    show_help
elif [[ "$CMD" = 'list' ]]; then
    if [ -n "$(echo "$@" | grep -o '\-d')" ]; then
        list -d
    else
        list
    fi
elif [[ "$CMD" = 'add' ]]; then
    add
elif [[ "$CMD" = 'drop' ]]; then
    drop
elif [[ "$CMD" = 'enable' ]]; then
    enable
elif [[ "$CMD" = 'disable' ]]; then
    disable
elif [[ "$CMD" = 'restore' ]]; then
    restore
elif [ "$CMD" == 'list-domains' ]; then
    list -d
elif [ "$CMD" == 'list-groups' ]; then
    list -g
else
  echo -e "\e[31mError: Unrecognized command $CMD\e[0m"
  echo
  show_help
fi
