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

#### Protocolo

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


#### Origem e destino

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

#### Porta

É onde fica o any
```
drop tcp $ HOME_NET any -> $ EXTERNAL_NET any
```

Tipos de regras as portas
: -> intervalos de porta
! -> exceção / negação
[.., ..] -> agrupamento


#### Direção

É a seta, Ex: ->

Só tem duas direções:
* ->
* <>

A direção informa de que maneira a assinatura deve corresponder. 

Por padrão é ->, a direção significa apenas que pacotes da mesma direção podem corresponder

Não tem o reverso <-

#### Opção de regra

O resto é opções das regras

Uma regra pode ter muitas ou nenhum opção encaixada nela, as regras são colocadas entre parentes e separadas por ponto e virgula, um exemplo de opção é o msg, que especifica palavras chaves da opção, caso a mesma não possua, é colocado um nocase no lugar

Vale comentar que as opções tem ordem a serem seguidas, caso uma dessas forem alteradas, o sentido da regra pode ser mudado

" e ; devem ser escapados no suricata para não ter problemas Ex: \" e |;

#### Palavras chaves modificadoras

Tem dois tipos de método:

* Antigo -> ```alert http any any -> any any (content:"index.php"; http_uri; sid:1;)```

O index é modificado para inspecioar o buffer HTTP URI

* Recente -> ```alert http any any -> any any (http_response_line; content:"403 Forbidden"; sid:1;)```

Esse é chamado de buffer fixo, ele coloca o nome do buffer primeiro e todas as palavras chaves são aplicadas nesse buffer.

No exemplo acima, é inspecionado a resposta HTTP porque segue a http_response_line na palavra chave

#### Buffers normalizados

Um pacote consiste em dados brutos. É feita uma copia dos dados do pacote e normalizado esses dados obtidos, com isso é feito uma interpretação dos mesmo e é aplicado as regras

#### Palavras chave meta

Essas não tem efeito no suricata, somente alterna a forma de relatar os eventos

#### msg

Fornece informações textuais sobre a assinatura e seu alerta

Padronização:
* Escapar caracteres: ;, \ e "
* Deixar a primeira parte da assinatura em maiusculo
* Mostrar a classe da assinatura
* Fazer a MSG a primeira palavra chave da assinatura

#### sid 

É um id unico de cada assinatura

Padronização
* Deve ser unico
* Deve ser o ultimo valor das opções da assinatura, somente fca atrás se houver um rev

#### rev

Rev quase sempre acompanha um sid, representa a versão da assinatura, sempre que a assinatura for alterada, esse valor deve ser incrementado

Padronização
* Se ele existir, ele sempre deve ser o ultimo valor da assinatura

#### Tipo de classes

O classtype fornece informações sobre a classe de regras e alertas, consiste em um nome curto, um longo e uma prioridade. Esse ponto pode dizer se é apenas informativo ou um problema real. Para cada tipo de classe, o cleanin.config tem uma prioridade para usar nessa regra.

Ex:
```
config classification: web-application-attack,Web Application Attack,1
config classification: not-suspicious,Not Suspicious Traffic,3
```

Tipo de classe, Alerta e prioridade.

Na regra ela fica listada assim:

```
classtype:trojan-activity
```

Padronização
* Ele é o ultimo antes do sid e rev

#### Referencia

É usado para orientar onde a assinatura deve ler para analisar, pode listar mais de uma informação ao mesmo tempo, esse ponto é mais para quem analisa e cria assinaturas.

Ex:
* ```reference: type, reference```
* ```reference: url, www.info.com```
* ```reference: cve, CVE-2014-1234```

#### Prioridade

É a prioridade a ser atendida na assinatura, sendo que varia de 1 a 255, do menor valor ao maior (quanto menor, maior a prioridade), porém é valido comentar que normalmente é usado até o 5.

Esse cara pode ser colocado em referencia e pode anular o referencia da palavra chave ou ser anulado pela referencia:

```priority:1```

#### Metados

É somente informação adicional, más por padronização é recomendavel colocar chave valor, Ex:```metadata: key value```

#### Alvo

Especifica qual lado do alerta é alvo do ataque, contem informações de origem e destino, Ex:
```
target:[src_ip|dest_ip]
```
Se o valor for src_ip, o IP de origem no evento gerado (campo src_ip em JSON) é o alvo do ataque. Se o destino for definido como dest_ip, o destino será o IP de destino no evento gerado.

#### ttl

A palavra-chave ttl é usada para verificar um valor de tempo de vida de IP específico no cabeçalho de um pacote. O formato é:
```
ttl:<number>
```

Se um pacote bate no tempo de vida, ele é destruido, P.S: Se o TTL tiver em 0, o pacote é automaticamente descartado.

#### ipopts

Verifica se o IP possui uma caracterisitca, se é colocado no inicio da regra e é somente possível combinar ele com uma opção da mesma regra.

* rr-> Rota de registro
* eol -> Fim da lista
* nop -> Sem op
* ts -> Carimbo de hora
* seg -> Segurança IP
* esec -> Segurança estendida de IP
* Isrr -> Roteamento de fonte solto
* ssrr -> Roteamento de fonte estrito
* satid -> Identificador de fluxo
* any -> Qualquer opção definida

Ex:
```
ipopts: <opção>
```

#### sameip 

Todo o pacote tem um ip origem/destino, essa opção confere se esse IP é igual entre ambos.

#### ip_proto

Pode combinar o protocolo IP no cabeçalho do pacote, podendo usar o nome ou numero do protocolo.

Ex (Não todos):
*  1     ICMP        Internet Control Message
*  6     TCP         Transmission Control Protocol
* 17     UDP         User Datagram
* 47     GRE         General Routing Encapsulation
* 50     ESP         Encap Security Payload for IPv6
* 51     AH          Authentication Header for Ipv6
* 58     IPv6-ICMP   ICMP for Ipv6

####  ipv4.hdr
Buffer fixo para corresponder a todo o cabeçalho IPv4.

####  ipv6.hdr
Buffer fixo para corresponder a todo o cabeçalho IPv6.

#### Identificação

O IP ID é usado como um número de identificação do fragmento.
Todos os fragmentos de um pacote tem o mesmo do ID.

Ex:
```
id:1;
```

#### geoip -> Precisa de API

Permite buscar o correspondente da origem, destino ou demais.
Suricata usa a API GeoIP2 da MaxMind.

* Ambas -> Ambas as direções devem corresponder ao (s) geoip (s) fornecido (s)
* qualquer -> Uma das direções deve corresponder ao (s) geoip (s) fornecido (s).
* dest -> Se o destino coincide com o geoip fornecido.
* src -> A fonte corresponde ao geoip fornecido.

A palavra-chave suporta apenas IPv4. Como ele usa a API GeoIP2 de MaxMind, libmaxminddb deve ser compilado.

#### fragbits 

Verifica se a fragmentação e os bits reservados estão definidos no cabeçalho IP.
Deve ser colocado no inicio da regra.
É usado para modificar o mecanismo de fragmentação, um exemplo é que pode haver pacotes maiores que o limite da rede, com isso, é usado esse mecanismo para fragmentar o pacote e fazer passar. 

Você pode combinar os seguintes bits:

* M - More Fragments
* D - Do not Fragment
* R - Reserved Bit

A correspondência nestes bits pode ser mais especificada com os seguintes modificadores:
```
+         match on the specified bits, plus any others
*         match if any of the specified bits are set
!         match if the specified bits are not set
```

Formato:
```
fragbits:[*+!]<[MDR]>;
```

#### fragoffset

Usado para remodelagem de fragmentos, permite adicionar valores decimais ao campo do fragmento, alterando o valor na remontagem ou mesmo o corrigindo

Modificadores:
* <       match if the value is smaller than the specified value
* >       match if the value is greater than the specified value
* !       match if the specified value is not present

Ex:
```
fragoffset:[!|<|>]<number>;
```

#### tos

Procura por valores decimais de 0 a 255 dentro do cabeçalho, Ex:
```
tos:[!]<number>;
```
Pode se usar mais de um tos por vez

#### TCP

#### seq

usada para verficiar uma sequencia TCP especifica
Seq e um valor gerado entre servidor e cliente, onde cada um recebe um valor diferente, porém a pilha TCP usa ele como referencia para guiar a entrega dos pacotes

#### seq

Cnfirmação de recebimento de todos os bytes transferidos pelo TCP, pode ser usado para confirmar uma conexao TCP em especifico.

#### Window

Usada para verificar o tamanho de uma página TCP especifica.
Mecanismo cd controle de fluxo de dados TCP.
O valor do tamanho da janela é limitado e pode ser de 2 a 65,535 bytes.

Ex: 
```
window:[!]<number>;
```

#### tcp.mss

Corresponde ao valor da opção TCP MSS. Não corresponderá se a opção não estiver presente.

#### tcp.hdr -> Esse foi copia na cara dura 

Buffer fixo para combinar com todo o cabeçalho TCP.

Regra de exemplo:
```
alert tcp $ EXTERNAL_NET any -> $ HOME_NET any (flags: S, 12; tcp.hdr; content: ”| 02 04 |”; offset: 20; byte_test: 2, <, 536,0, grande, relativo; sid: 1234; rev: 5;)
```

Este exemplo começa a olhar para a parte fixa do cabeçalho, para as opções de tamanho variável. Lá ele irá procurar a opção MSS (tipo 2, opção len 4) e usando um byte_test determinar se o valor da opção é menor que 536. A opção tcp.mss será mais eficiente, então esta palavra-chave deve ser usada nos casos em que nenhuma palavra-chave específica está disponível.