# OCI Network Security Manager

## Isenção de responsabilidade

>Antes de continuar, quero avisar que a utilização das informações, comandos, códigos e scripts é de total responsabilidade sua (usuário), ficando assim você (usuário) responsável por qualquer tipo de utilização que você possa vir a fazer do que irá encontrar nesta página.
>
>Teste adequadamente em recursos de teste antes de usar em recursos de produção para evitar interrupções indesejadas ou contas muito caras.
>
>Este não é um aplicativo oficial da Oracle e por isso, não conta com o seu suporte. A Oracle não se responsabiliza por nenhum conteúdo aqui presente.

### Descrição

Esse script se destina a facilitar a criação em lote de novas regras de segurança em uma NSG (_Network Security Group_).

1. [Funcionalidades](#funcionalidades)
    1.1. [Identificação de regras duplicadas](#identificacao-de-regras-duplicadas)
    1.2. [Identificação de regras preexistentes](#identificacao-de-regras-preexistentes)
    1.3. [Identificação de IP em CIDR](#identificacao-de-ip-em-cidr)
    1.4. [Implementação de regras até o limite suportado](#implementacao-de-regras-ate-o-limite-suportado)
    1.5. [Implementação das regras em um único lote](#implementacao-das-regras-em-um-unico-lote)
    1.6. [Execução de teste/validação (read-only)](#execucao-de-teste-validacao-read-only)
    1.7. [Utilização dos protocolos TCP/UDP](#utilizacao-dos-protocolos-tcp-udp)
    1.8. [Porta de acesso](#portas-de-acesso)
    1.9. [Suporte a range de IPs](#suporte-a-range-de-ips)
    1.10. [Suporte a CIDR](#suporte-a-cidr)
2. [Autenticação suportadas](#autenticação-suportadas)
3. [Como Utilizar](#como-utilizar)
    3.1. [Exemplo de arquivo de entrada](#exemplo-de-arquivo-de-entrada)
    3.2. [Lista completa de parâmetros](#lista-completa-de-parâmetros)

#### Funcionalidades

- ##### Identificação de regras duplicadas {#identificacao-de-regras-duplicadas}

    A identificação é feita no arquivo de entrada, especificado por parâmetro, como sendo a lista das regras **ingress**/**egress** a ser implementada.
    As regras presentes no arquivos sao verificadas para identificar duplicidade entre elas e nao implantar a mesma regra 2 vezes.
    Parâmetro(s) que pode(m) ser utilizado(s):
    &nbsp;
    >&nbsp;
    >-if | --lst-ingress-orig-port
    >-ef | --lst-egress-dest-port
    >-id | --lst-ingress-orig-dest-port [**DEPRECATED**]
    >-ed | --lst-egress-orig-dest-port [**DEPRECATED**]
    >&nbsp;

    **\* Verifique a [Lista completa de parâmetros](#lista-completa-de-parâmetros) para mais detalhes**
    &nbsp;

- ##### Identificação de regras preexistentes {#identificacao-de-regras-preexistentes}

    A validação é feita nas regras preexistentes na [NSG]( . "Network Security Group") especificada como alvo da implementação das regras e/ou na lista de validação especificada por parâmetros.
    Parâmetro(s) que pode(m) ser utilizado(s):
    &nbsp;
    >&nbsp;
    > -n | --nsg-ocid
    > -l | --nsg-ocid-list
    >&nbsp;

    **\* Verifique a [Lista completa de parâmetros](#lista-completa-de-parâmetros) para mais detalhes**
    &nbsp;

- ##### Identificação de IP em CIDR {#identificacao-de-ip-em-cidr}

    O mecanismo de identificação de regras preexistentes pode identificar endereços IP que já possuem a liberação solicitada por fazer parte de um CIDR liberado previamente.
    &nbsp;

- ##### Implementação de regras até o limite suportado {#implementacao-de-regras-ate-o-limite-suportado}

    O método padrão de trabalho do script é implementar as regras de segurança até que o limite de regras suportada por uma [NSG]( . "Network Security Group") seja alcançado. Veja o link [OCI Service Limits: Network Security Group](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#nsg_limits) para mais detalhes.
    Se a implementação tiver mais regras do que a [NSG]( . "Network Security Group") suportar, será implementada as primeiras regras identificadas e as demais serão ignoradas.
    &nbsp;

- ##### Implementação das regras em um único lote {#implementacao-das-regras-em-um-unico-lote}

    Utilizando um parâmetro específico, é possível mudar como o script se comporta ao chegar ao limite de regras suportado por uma [NSG]( . "Network Security Group").
    O parâmetro abaixo especifica que **TODAS** as regras do arquivo de entrada deve ser implementada nessa execução do script, caso não seja possível, **NENHUMA REGRA** deve ser implementada.
    Parâmetro(s) que pode(m) ser utilizado(s):
    &nbsp;
    >&nbsp;
    > -a, --all-in
    >&nbsp;

    **\* Verifique a [Lista completa de parâmetros](#lista-completa-de-parâmetros) para mais detalhes**
    &nbsp;

- ##### Execução de teste/validação (read-only) {#execucao-de-teste-validacao-read-only}

    Você pode executar o script em **Read-Only Mode** para identificar as alterações e validações que serão feitas.
    Parâmetro(s) que pode(m) ser utilizado(s):
    &nbsp;
    >&nbsp;
    > -t, --dry-run
    >&nbsp;

    **\* Verifique a [Lista completa de parâmetros](#lista-completa-de-parâmetros) para mais detalhes**
    &nbsp;

- ##### Utilização dos protocolos TCP/UDP {#utilizacao-dos-protocolos-tcp-udp}

    O script suporta a utilização dos protocolos **UDP** e **TCP** na liberação das regras de segurança.
    Utilize a seguinte notação no arquivo de entrada:
    &nbsp;
    >&nbsp;
    > 10.3.6.10 **tcp**/22
    > 10.6.2.22 **udp**/53
    >&nbsp;

- ##### Porta de acesso {#portas-de-acesso}

    Para a liberação de uma regra de segurança, você pode especificar 1 ou múltiplas portas de acesso, utilize o **;** entre a especificação do protocolo "**/**" porta.
    Abaixo um exemplo da notação descrita:
    &nbsp;
    >&nbsp;
    > 10.16.32.122 tcp/22
    > 10.30.62.101 tcp/5900;tcp/5800;tcp/5938;udp/5938
    >&nbsp;

- ##### Suporte a Range de IPs {#suporte-a-range-de-ips}

    É possível especificar range de IPs no arquivo de entrada fazendo uso da seguinte notação.
    &nbsp;
    >&nbsp;
    > _**10.1.2.5**_-_**10.1.2.10**_ tcp/22
    >&nbsp;

    Assim, será criada uma regra para cada endereço IP entre "**10.1.2.5**" e "**10.1.2.10**" para acesso a porta TCP/22

- ##### Suporte a CIDR {#suporte-a-cidr}

    É possível especificar um CIDR no arquivo de entrada fazendo uso da seguinte notação.
    &nbsp;
    >&nbsp;
    > 10.6.2.0/24
    > 172.16.0.0/16
    > 192.168.2.128/25
    >&nbsp;

### Autenticação suportadas

- [CLI Configuration File](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/cliconfigure.htm)
- [Token-based Authentication](https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clitoken.htm#Running_Scripts_on_a_Computer_without_a_Browser)

#### Como Utilizar

Para executar esse script você precisa fazer o download do script para o [OCI Cloud Shell](https://docs.oracle.com/pt-br/iaas/Content/API/Concepts/cloudshellintro.htm "Oracle Cloud Infrastructure Cloud Shell") e depois executá-lo com os parâmetros necessários.
Para tanto, siga os passos abaixo:

**Download**:

``` shell
curl -L "https://raw.githubusercontent.com/oracle/oci-python-sdk/master/examples/showoci/showoci_upgrade.sh"
```

**Exemplo de execusão**:
>&nbsp;
> ./**oci_mgn_vcn_nsg.py** \
> --**rule-description** "Mudanca 1604" \
> --**lst-ingress-orig-port** arq_ingress_rules.lst \
> --**lst-egress-dest-port** arq_egress_rules.lst \
> --**nsg-ocid** \
> ocid1.networksecuritygroup.oc1.{region}.{sample_01} \
> --**nsg-ocid-list** \
> ocid1.networksecuritygroup.oc1.{region}.{sample_02} \
> ocid1.networksecuritygroup.oc1.{region}.{sample_03} \
> ocid1.networksecuritygroup.oc1.{region}.{sample_04}
>
> - **Lembre-se de alterar os valores conforme sua necessidade.**
>&nbsp;

##### Exemplo de arquivo de entrada

É possível especificar os endereços IP de 3 formas diferentes:

- Endereco IP
Especifique um endereço respeitando as [notações possíveis](https://en.wikipedia.org/wiki/IP_address "Internet Protocol address").
    > 192.168.0.1

- Range de Endereços IP
Seguindo as mesma definições de um "Endereço IP" especificadas acima, você pode fazer a seguinte notação para espeficar mais de 1 endereco:
    > **192.168.32.2**-**192.168.32.5**

- [CIDR](https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing "Classless Inter-Domain Routing") block
    > 172.16.0.0/16

O arquivo de entrada ainda aceita comentários precedidos do símbolo "**#**" e permite linhas em branco.

**Exemplo:**

``` shell
# Origem TCP/UDP_Port1;TCP/UDP_Port2
172.16.10.0/24 tcp/22;
172.16.20.0/25 tcp/1521;tcp/1443;tcp/3306

192.168.30.10-192.168.30.11 tcp/3389;
192.168.40.20 tcp/21;tcp/5500-57000;tcp/1500-1501

10.1.3.5 udp/2202
10.10.1.0/24 tcp/80;tcp/443
```

##### Lista completa de parâmetros

> -id, --**lst-ingress-orig-dest-port** <**FILE_NAME**> [**DEPRECATED**]
> Arquivo com a lista de regras INGRESS,
> organizado em colunas separadas por espaço.
>  [**ORIGEM**] [**DESTINO**] [**PORTA**]
>
> -ed, --**lst-egress-orig-dest-port** <**FILE_NAME**> [**DEPRECATED**]
> Arquivo com a lista de regras EGRESS,
> organizado em colunas separadas por espaço.
>  [**ORIGEM**] [**DESTINO**] [**PORTA**]
>
> -if, --**lst-ingress-orig-port** <**FILE_NAME**>
> Arquivo com a lista de regras INGRESS,
> organizado em colunas separadas por espaço.
>  [**ORIGEM**] [**PORTA**]
>
> -ef, --**lst-egress-dest-port** <**FILE_NAME**>
> Arquivo com a lista de regras INGRESS,
> organizado em colunas separadas por espaço.
> [**DESTINO**] [**PORTA**]
>
> -d, --**rule-description** <**RULE_DESCRIPTION**>
> Descrição para todas as regras adicionadas pelo script.
> Ex: --rule-description "Regra aprovada pelo mudanca 1604"
>
> -n, --**nsg-ocid** <**NSG_OCID**>
> OCID da [NSG]( . "Network Security Group") que receberá as regras.
>
> -l, --**nsg-ocid-list** [NSG1_OCID, NSG2_OCID, ...]
> Lista de OCIDs de [NSG]( . "Network Security Group")s que serão analisadas para identificar
> regras previamente implementadas.
>
> -c, --**config** <**OCI_CLI_CONFIG_FILE**>
> O método padrão de autenticação é o (**Token Delegation**) utilizado
> pelo (**Choud Shell**) por padrão. Mas você pode usar o arquivo de
> configuração "~/.oci/config" do próprio "oci cli", caso esteja executando
> esse script em outro local.
>
> -a, --**all-in**
> A implementação das regras será efetuada, apenas se todas as regras
> puderem ser implementadas nessa execução, respeitando o limite de
> regras Ingress/Egress por [NSG]( . "Network Security Group") descritas em: [OCI Service Limits: Network Security Group](https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#nsg_limits)
>
> -t, --**dry-run**
> Executa o script em (read-only), não executando a implementação das
>regras ao final da execução.
>&nbsp;
