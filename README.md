# hosts-cli
A CLI to handle /etc/hosts file as a local DNS resolver

## Install

```bash
wget -q -O - https://raw.githubusercontent.com/codeccoop/hosts-cli/main/install.sh | bash -
source .profile
```

## Usage

* Show help: 
* Add a domain: `dns add [-i x.x.x.x] [-g group] example.com`
* Drop a domain: `dns drop [-s] example.com`
* Enable domains: `dns enable [-s] [-g group] [example.com]`
* Disable domains: `dns disable [-s] [-g group] [example.com]`
