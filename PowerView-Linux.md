## Instalar suporte a venv, caso ainda não tenha
sudo apt install python3-venv -y

## Criar ambiente virtual (você pode escolher outro caminho se quiser)
python3 -m venv ~/venvs/powerview

## Ativar o ambiente virtual
source ~/venvs/powerview/bin/activate

## Instalar o pacote dentro do ambiente virtual
pip install powerview


powerview 'domain/user:P@ssw0rd'@192.168.0.9

─LDAP─[SRVAD01.domain.local]─[DOMAIN\licenca]-[NS:192.168.0.9]
╰─PV ❯ 
