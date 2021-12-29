#### Resumo suricata

IDS -> Sistema de detecção de intrusão
IPS -> Sistema de prevenção de intrusão

Suricata precisa de pacotes do Snort para funcionar

Instalação em distros baseadas no debian:
```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata jq
```

Confirmar configurações do suricata:
```
sudo suricata --build-info
sudo systemctl status suricata
```

Arquivo de configurações do suricata:
```
sudo vim /etc/suricata/suricata.yaml
```
A váriavel ```HOME_NET``` é para todos os IP's monitorados pela interface

As configurações da interface ficam dentro do YAML, na parte de:
```
af-packet:
```

Suricata usa assinaturas/regras para funcionar

Atualizar regras: ```suricata-update```
Local: ```/var/lib/suricata/rules```
Arquivo unico padrão: ```suricata.rules```
Logs: ```/var/log/suricata/suricata.log```

Na ultima linha de log, se mostra as configurações de threads em uso:
```
<Notice> - all 4 packet processing threads, 4 management threads initialized, engine started.
```

Status do suricata: ```/var/log/suricata/stats.log```
* Quantidade de pacotes processos e trafego decodificado

Alertas: ```/var/log/suricata/fast.log```

Leitura dos logs json
```
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")|.stats.capture.kernel_packets'
sudo tail -f /var/log/suricata/eve.json | jq 'select(.event_type=="stats")
```
1 -> Pacotes capturados pelo kernel
2 -> Todas as estátisticas

Suricata pode ser atualizado facilmente
- Sobrescrevendo o atual por um novo

Se um suricata for atualizado, os arquivos de configuração e referencia serão renomeados para não serem sobrescritos, após isso é necessários confirmar as diferenças manualmente e alterar os arquivos conforme a demanda.

Comands:
Opções de linha de comando de Suricata:

* ```-h``` -> Exibe uma breve visão geral do uso.
* ```-V``` -> Exibe a versão do Suricata.
* ```-c  <path>``` -> Caminho para o arquivo de configuração.
* ```-T``` -> Configuração de teste.
* ```-i``` -> Da a opção de selecionar uma interface a fazer a operação
* ```-S``` -> Da a opção de usar um arquivo exclusivo das demais regras existentes, Ex: 5 regras padrão + 1 extra
* ```-D``` -> Modo deamon -> Roda em background
* ```--build-info``` -> Informações da build do suricata
* ```--list-runmodes``` -> Lista todos os modos de execução suportado
* ```--set``` -> Força a seguir parametros passados no command line 

Exemplo de uma regra

```
drop tcp $ HOME_NET any -> $ EXTERNAL_NET any (msg: ”ET TROJAN Provável Bot Nick no IRC (USA + ..)”; flow: estabelecido, to_server; flowbits: isset, is_proto_irc; conteúdo: ”NICK“; pcre: ” / NICK. * USA. * [0-9] {3,} / i ”; referência: url, doc.emergingthreats.net / 2008124; tipo de classe: trojan-activity; sid: 2008124; rev: 2;)
```

drop -> Ação da regra
tcp $ HOME_NET any -> $ EXTERNAL_NET any -> Cabeçalho
O reto -> Opções da regra

As ações válidas são:

alert - gera um alerta
aprovado - interrompe a inspeção adicional do pacote
drop - descarte o pacote e gere alerta
rejeitar - enviar erro de não alcance RST / ICMP ao remetente do pacote correspondente.
rejeita rc - o mesmo que apenas rejeitar
Rejeitdst - envia o pacote de erro RST / ICMP ao receptor do pacote correspondente.
rejeitarboth - enviar pacotes de erro RST / ICMP para ambos os lados da conversa.

Protocolo

Esta palavra-chave em uma assinatura informa a Suricata a qual protocolo ela se refere. Você pode escolher entre quatro protocolos básicos:

* tcp (para tráfego tcp)
* udp
* icmp
* ip (ip significa 'todos' ou 'qualquer')

Existem também alguns chamados protocolos da camada de aplicativo, ou protocolos da camada 7, que você pode escolher. Estes são:

* http
* ftp
* tls (inclui SSL)
* SMB
* dns
* dcerpc
* ssh
* smtp
* imap
* modbus (desabilitado por padrão)
* dnp3 (desabilitado por padrão)
* enip (desabilitado por padrão)
* nfs
* ikev2
* krb5
* ntp
* dhcp
* rfb
* rdp
* snmp
* tftp
* trago
* http2

A disponibilidade desses protocolos depende se o protocolo está habilitado no arquivo de configuração suricata.yaml.

Se você tiver uma assinatura com, por exemplo, um protocolo http, Suricata garante que a assinatura só pode coincidir se for relativo ao tráfego http.


Origem e destino

Ip de entrada e saida
Direção da seta influencia
Valido tanto ip4 e ip6 -> Pode se usar intervalos e váriaveis

Ex: ```drop tcp $ HOME_NET any -> $ EXTERNAL_NET any```

É possível usar agrupamentos, Ex:

../ .. -> Intervalos de IP (notação CIDR)
! -> exceção / negação
[.., ..] -> agrupamento


Exemplos
* !1.1.1.1	-> Cada endereço IP, exceto 1.1.1.1
* ![1.1.1.1, 1.1.1.2] -> Cada endereço IP, exceto 1.1.1.1 e 1.1.1.2
* $HOME_NET -> Sua configuração de HOME_NET no yaml
* [$EXTERNAL_NET,!$ HOME_NET] -> EXTERNAL_NET e não HOME_NET
* [10.0.0.0/24,! 10.0.0.5] -> 10.0.0.0/24 exceto para 10.0.0.5


Porta

É onde fica o any
```
drop tcp $ HOME_NET any -> $ EXTERNAL_NET any
```

Tipos de regras as portas
: -> intervalos de porta
! -> exceção / negação
[.., ..] -> agrupamento


Direção

É a seta, Ex: ->

Só tem duas direções:
* ->
* <>

