#! /bin/bash

cd $HOME

mkdir -p .local/bin
wget -O .local/bin/dns https://raw.githubusercontent.com/codeccoop/hosts-cli/main/hosts-cli.sh
chmod +x .local/bin/dns

mkdir -p .local/share/bash-completion/completions
wget -O .local/share/bash-completion/completions/hosts-cli https://raw.githubusercontent.com/codeccoop/hosts-cli/main/bash-completion.sh

config_file="$(test -f ".bashrc" && echo ".bashrc" || echo ".profile")"
echo '# hosts-cli completion script' >> $config_file
echo 'source ~/.local/share/bash-completion/completions/hosts-cli' >> $config_file

source $config_file
