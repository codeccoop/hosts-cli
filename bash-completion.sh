_hosts_cli_complete() {
    local cur opts prev
    COMPREPLY=()
	if [ -z "$(grep -Po 'disable|drop|enable' <<< "${COMP_WORDS[@]}")" ]; then
	    return 0
	fi
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    if [ "$prev" == '-g' ]; then
        opts=$(dns list-groups)
    else
        opts=$(dns list-domains)
    fi
   	COMPREPLY=( $(compgen -W "${opts}" -- ${cur}) )
    return 0
}
complete -F _hosts_cli_complete dns
