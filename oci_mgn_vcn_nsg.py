#!/bin/env python
# =============================================================================
# OCI - Manager VCN NSG Rules
#
# Created by: Igor Nicoli
# =============================================================================

try:
    import oci
except ImportError as error:
    print(error)
    print("")
    print("OCI libraries not installed. Please install them with 'pip3 install oci'")
    exit(-1)

import re
import os
import sys
import ipaddress
from genericpath import isfile
from argparse import ArgumentParser, ArgumentDefaultsHelpFormatter

# -----------------------------------------------------------------------------
# Regex para identificar ipv4
REGEX_IPV4 = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
REGEX_IPV4_ONLY = re.compile("^"+REGEX_IPV4.pattern+"$")
REGEX_IPV4_CIDR = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/(3[0-2]|[1-2]?\d)$")
REGEX_IPV4_RANGE = re.compile(REGEX_IPV4.pattern + '-' +REGEX_IPV4.pattern)

# -----------------------------------------------------------------------------
# Sentido das regras de liberacao em NSG
rule_directions=['ingress', 'egress']

# -----------------------------------------------------------------------------
# Lista de protocolos para utilizacao na security lista, traduzindo-o para o
# codigo numerico correlato:
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
SECURITY_LIST_PROTOCOL={'TCP':6,'UDP':17,6:"TCP",17:"UDP"}

# -----------------------------------------------------------------------------
# Limite de quantidade de regras em uma security lista
# https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#nsg_limits
RULES_LIMIT=120

# -----------------------------------------------------------------------------
# lista de cores para output do script:
color = {
    'cyan':'\033[36m' ,
    'purple':'\033[35m' ,
    'blue':'\033[34m',
    'yellow':'\033[33m',
    'green':'\033[32m',
    'red':'\033[31m',
    'red_blink':'\x1b[6;37;41m',
    'clean':'\033[0m'
}

# -----------------------------------------------------------------------------
class Unbuffered(object):
   def __init__(self, stream):
       self.stream = stream
   def write(self, data):
       self.stream.write(data)
       self.stream.flush()
   def writelines(self, datas):
       self.stream.writelines(datas)
       self.stream.flush()
   def __getattr__(self, attr):
       return getattr(self.stream, attr)

# -----------------------------------------------------------------------------
def ip_to_binary(ip):
    octet_list_int = ip.split(".")
    octet_list_bin = [format(int(i), '08b') for i in octet_list_int]
    binary = ("").join(octet_list_bin)
    return binary

# -----------------------------------------------------------------------------
def get_addr_network(address, net_size):
    #Convert ip address to 32 bit binary
    ip_bin = ip_to_binary(address)
    #Extract Network ID from 32 binary
    network = ip_bin[0:32-(32-net_size)]    
    return network

# -----------------------------------------------------------------------------
def ip_in_prefix(ip_address, prefix):
    #CIDR based separation of address and network size
    [prefix_address, net_size] = prefix.split("/")
    #Convert string to int
    net_size = int(net_size)
    #Get the network ID of both prefix and ip based net size
    prefix_network = get_addr_network(prefix_address, net_size)
    ip_network = get_addr_network(ip_address, net_size)
    return ip_network == prefix_network

# -----------------------------------------------------------------------------
def check_ipv4_type(ipv4_string):
    ipv4_type=None

    ipv4_string=re.sub(r"\/32$", "", ipv4_string)

    if re.match(REGEX_IPV4_ONLY, ipv4_string):
        ipv4_type='ipv4_address'

    elif re.match(REGEX_IPV4_RANGE, ipv4_string):
        ipv4_type='ipv4_range'

    elif re.match(REGEX_IPV4_CIDR, ipv4_string):
        ipv4_type='ipv4_cidr'

    return(ipv4_type)

# -----------------------------------------------------------------------------
def make_ipv4_address_list(ipv4_string):
    """
    """
    ipv4_to_return=list()
    ipv4_status=False
    ipv4_type=check_ipv4_type(ipv4_string)
    # Processa o block de origem:
    if ipv4_type == "ipv4_address":
        ipv4_to_return.append('%s/32' % str(ipv4_string))
        ipv4_status=True

    elif ipv4_type == "ipv4_range":
        ip_range = ipv4_string.split('-')
        start_ip = ipaddress.IPv4Address(ip_range[0])
        end_ip = ipaddress.IPv4Address(ip_range[1])
        for ip_int in range(int(start_ip), int(end_ip)):
            ipv4_to_return.append('%s/32' % str(ipaddress.IPv4Address(ip_int)))
        ipv4_to_return.append('%s/32' % ip_range[1])
        ipv4_status=True

    elif ipv4_type == "ipv4_cidr":
        ipv4_to_return.append(str(ipv4_string))
        ipv4_status=True

    else:
        print('     [%sERRO%s] IP/Range ou CIDR Invalido :[%s]' % (color['red'],color['clean'],ipv4_string))

    return(ipv4_to_return,ipv4_status)

# -----------------------------------------------------------------------------
def get_nsg_rules(vnet_client, nsg_list):
    """
    """
    nsg_rules={'ingress':list(), 'egress':list()}
    for nsg_ocid in nsg_list:
        for rule in oci.pagination.list_call_get_all_results(
            vnet_client.list_network_security_group_security_rules,
            network_security_group_id=nsg_ocid,
            direction="INGRESS"
        ).data:
            nsg_rules['ingress'].append(rule)

        for rule in oci.pagination.list_call_get_all_results(
            vnet_client.list_network_security_group_security_rules,
            network_security_group_id=nsg_ocid,
            direction="EGRESS"
        ).data:
            nsg_rules['egress'].append(rule)

    return(nsg_rules)

# -----------------------------------------------------------------------------
def get_nsg_info(vnet_client, nsg_ocid):
    """
    """
    get_nsg_resp = vnet_client.get_network_security_group(
        network_security_group_id=nsg_ocid
    ).data

    nsg_info={
        'name':get_nsg_resp.display_name,
        'rules_count':0
    }

    # -------------------------------------------------------------------------
    # Lista e contabiliza as regras da NSG:
    for rule_direction in rule_directions:
        nsg_info['rules_count']+=len(oci.pagination.list_call_get_all_results(
            vnet_client.list_network_security_group_security_rules,
            network_security_group_id=nsg_ocid,
            direction=(rule_direction).upper()
        ).data)
        del(rule_direction)

    return(nsg_info)

# -----------------------------------------------------------------------------
def check_duplicate_rules(rules):
    """
    """
    DDUP_RULES=list()

    # -------------------------------------------------
    # Lista as novas regras por tipo de protocolo:
    for protocol in ['tcp', 'udp', 'icmp']:
        proto_option=('%s_options' % protocol)
        for rule in rules:
            # -----------------------------------------------------------------
            # invoca attributos de forma customizada, conforme o
            # protocolo ou o sentido da regra INGRESS/EGRESS:
            rule_options=getattr(rule, proto_option)
            if rule.direction == 'INGRESS':
                target_name='source'
                rule_target=rule.source
            elif rule.direction == 'EGRESS':
                target_name='dest'
                rule_target=rule.destination

            RULE_FOUND=False
            if rule_options == None:
                continue
            # Lista as regras existentes:
            for copy_rule in DDUP_RULES:

                # -----------------------------------------------------------------
                # invoca attributos de forma customizada, conforme o
                # protocolo ou o sentido da regra INGRESS/EGRESS:
                copy_rule_options=getattr(copy_rule, proto_option)
                if rule.direction == 'INGRESS':
                    copy_rule_target=copy_rule.source
                elif rule.direction == 'EGRESS':
                    copy_rule_target=copy_rule.destination

                if copy_rule_options == None:
                    continue
                
                pre_exist_validation=False
                if (check_ipv4_type(copy_rule_target) == 'ipv4_cidr' and check_ipv4_type(rule_target) == 'ipv4_address'):
                    if ip_in_prefix(re.sub(r"\/32$", "", rule_target), copy_rule_target):
                        if (rule_options.destination_port_range.min == copy_rule_options.destination_port_range.min and
                            rule_options.destination_port_range.max == copy_rule_options.destination_port_range.max):
                            pre_exist_validation=True

                elif (rule_target == copy_rule_target and
                    rule.protocol == copy_rule.protocol and
                    rule_options.destination_port_range.min == copy_rule_options.destination_port_range.min and
                    rule_options.destination_port_range.max == copy_rule_options.destination_port_range.max):
                        pre_exist_validation=True

                if pre_exist_validation:
                    RULE_FOUND=True
                    if rule_options.destination_port_range.min == rule_options.destination_port_range.max:
                        port=rule_options.destination_port_range.max
                    else:
                        port=('%s-%s' % (
                            rule_options.destination_port_range.min,
                            rule_options.destination_port_range.max
                        ))
                    
                    print(" [%sWARN%s] |       |-> %sDUPLICATED %s RULE%s - %s:%s, port:%s/%s" % (
                        color['yellow'],color['clean'],color['yellow'],rule.direction,color['clean'],
                        target_name,rule_target,SECURITY_LIST_PROTOCOL[int(copy_rule.protocol)],port
                    ))
                    break
            if RULE_FOUND == False:
                DDUP_RULES.append(rule)

    return(DDUP_RULES)

# -----------------------------------------------------------------------------
def check_exist_rules(new_rules, old_rules):
    """
    """

    # -------------------------------------------------
    # Lista das regras novas, que nao existem no ambiente:
    nsg_new_rules=list()

    for protocol in ['tcp', 'udp', 'icmp']:
        proto_option=('%s_options' % protocol)
        count_rule=0
        for new_rule in new_rules:
            count_rule+=1
            # -----------------------------------------------------------------
            # invoca attributos de forma customizada, conforme o
            # protocolo ou o sentido da regra INGRESS/EGRESS:
            rule_options=getattr(new_rule, proto_option)
            if new_rule.direction == 'INGRESS':
                rule_target=new_rule.source
            elif new_rule.direction == 'EGRESS':
                rule_target=new_rule.destination

            RULE_FOUND=False
            if rule_options == None:
                continue
            # Lista as regras existentes na subnet_list:
            for old_rule in old_rules:

                # -----------------------------------------------------------------
                # invoca attributos de forma customizada, conforme o
                # protocolo ou o sentido da regra INGRESS/EGRESS:
                old_rule_options=getattr(old_rule, proto_option)
                if new_rule.direction == 'INGRESS':
                    old_rule_target=old_rule.source
                elif new_rule.direction == 'EGRESS':
                    old_rule_target=old_rule.destination

                if old_rule_options == None:
                    continue

                pre_exist_validation=False
                if (check_ipv4_type(old_rule_target) == 'ipv4_cidr' and check_ipv4_type(rule_target) == 'ipv4_address'):
                    if ip_in_prefix(re.sub(r"\/32$", "", rule_target), old_rule_target):
                        if (rule_options.destination_port_range.min == old_rule_options.destination_port_range.min and
                            rule_options.destination_port_range.max == old_rule_options.destination_port_range.max):
                            pre_exist_validation=True

                elif (rule_target == old_rule_target and
                    new_rule.protocol == old_rule.protocol and
                    rule_options.destination_port_range.min == old_rule_options.destination_port_range.min and
                    rule_options.destination_port_range.max == old_rule_options.destination_port_range.max):
                        pre_exist_validation=True

                if pre_exist_validation:
                        RULE_FOUND=True
                        if rule_options.destination_port_range.min == rule_options.destination_port_range.max:
                            port=rule_options.destination_port_range.max
                        else:
                            port=('%s-%s' % (
                                rule_options.destination_port_range.min,
                                rule_options.destination_port_range.max
                            ))
                        if count_rule == len(new_rules):
                            print(" [%sWARN%s] |       `-> [%03d] %sEXIST%s - %s:%s, port:%s/%s" % (
                                color['yellow'],color['clean'],count_rule,color['yellow'],color['clean'],
                                new_rule.direction,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                            ))
                        else:
                            print(" [%sWARN%s] |       |-> [%03d] %sEXIST%s - %s:%s, port:%s/%s" % (
                                color['yellow'],color['clean'],count_rule,color['yellow'],color['clean'],
                                new_rule.direction,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                            ))
                        break
            if RULE_FOUND == False:
                nsg_new_rules.append(new_rule)
                if rule_options.destination_port_range.min == rule_options.destination_port_range.max:
                    port=rule_options.destination_port_range.max
                else:
                    port=('%s-%s' % (
                        rule_options.destination_port_range.min,
                        rule_options.destination_port_range.max
                    ))
                if count_rule == len(new_rules):
                    print(" [ %sOK%s ] |       `-> [%03d] %sN-E-W%s - %s:%s, port:%s/%s" % (
                        color['green'],color['clean'],count_rule,color['green'],color['clean'],
                        new_rule.direction,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                    ))
                else:
                    print(" [ %sOK%s ] |       |-> [%03d] %sN-E-W%s - %s:%s, port:%s/%s" % (
                        color['green'],color['clean'],count_rule,color['green'],color['clean'],
                        new_rule.direction,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                    ))

    return(nsg_new_rules)

# -----------------------------------------------------------------------------
CUSTOM_RETRY_STRATEGY = oci.retry.RetryStrategyBuilder(
    # Make up to 10 service calls
    max_attempts_check=True,
    max_attempts=10,

    # Don't exceed a total of 600 seconds for all service calls
    total_elapsed_time_check=True,
    total_elapsed_time_seconds=600,

    # Wait 45 seconds between attempts
    retry_max_wait_between_calls_seconds=45,

    # Use 2 seconds as the base number for doing sleep time calculations
    retry_base_sleep_time_seconds=2,

    # Retry on certain service errors:
    #
    #   - 5xx code received for the request
    #   - Any 429 (this is signified by the empty array in the retry config)
    #   - 400s where the code is QuotaExceeded or LimitExceeded
    service_error_check=True,
    service_error_retry_on_any_5xx=True,
    service_error_retry_config={
        400:['QuotaExceeded', 'LimitExceeded'],
        429:[]
    },

    # Use exponential backoff and retry with full jitter, but on throttles use
    # exponential backoff and retry with equal jitter
    backoff_type=oci.retry.BACKOFF_FULL_JITTER_EQUAL_ON_THROTTLE_VALUE
).get_retry_strategy()

# ==============================================================================
# funcao principal:
if __name__ == '__main__':
    # -----------------------------------------------------------------------------
    # Desativa o buffer de saida no stdour (console)
    sys.stdout = Unbuffered(sys.stdout)

    # -----------------------------------------------------------------------------
    # Configuracao dos parametros do script:
    parser = ArgumentParser(
        allow_abbrev=False,
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="Script de coleta de dados de performace (OPDR - Oracle Performance Data Report) e inventario de instaces em ambiente OCI.",
    )
    parser.add_argument('-id', '--lst-ingress-orig-dest-port', default='/dev/null', help="[DEPRECATED] Lista de regras INGRESS com as colunas [ORIGEM] [DESTINO] [PORTA]") 
    parser.add_argument('-if', '--lst-ingress-orig-port', default='/dev/null', help="Lista de regras INGRESS com as colunas [ORIGEM] [PORTA]") 
    parser.add_argument('-ed', '--lst-egress-orig-dest-port', default='/dev/null', help="[DEPRECATED] Lista de regras EGRESS com as colunas [ORIGEM] [DESTINO] [PORTA]") 
    parser.add_argument('-ef', '--lst-egress-dest-port', default='/dev/null', help="Lista de regras EGRESS com as colunas [DESTINO] [PORTA]") 
    parser.add_argument('-d', '--rule-description', default=None, help="Descrição para todas as regras adicionadas pelo script. Ex: --rule-description \"Regra aprovada pelo mudanca 1604\"") 
    parser.add_argument('-n', '--nsg-ocid', default=None, help="OCID da NSG que receberá as regras.") 
    parser.add_argument('-l', '--nsg-ocid-list', nargs='*', help="Lista de OCIDs de NSGs que serão analisadas para identificar regras previamente implementadas.") 
    parser.add_argument('-c', '--config', default=None, help="O método padrão de autenticação é o (Token Delegation) utilizado pelo (Choud Shell) por padrão. Mas você pode usar o arquivo de configuração \"~/.oci/config\" do próprio \"oci cli\", caso esteja executando esse script em outro local.") 
    parser.add_argument('-a', '--all-in', action="store_true", default=False, help="A implementação das regras será efetuada, apenas se todas as regras puderem ser implementadas nessa execução, respeitando o limite de regras Ingress/Egress por NSG descritas em: https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#nsg_limits") 
    parser.add_argument('-t', '--dry-run', action="store_true", default=False, help="Executa o script em (read-only), não executando a implementação das regras ao final da execução.")
    args = parser.parse_args()

    # -----------------------------------------------------------------------------
    # Verifica se o arquivo de regras existe:
    INPUT_FILES={
        'ingress':{'file':None,'dest':False},
        'egress':{'file':None,'dest':False}
    }
    if (isfile(args.lst_ingress_orig_dest_port) or isfile(args.lst_ingress_orig_port) or 
        isfile(args.lst_egress_orig_dest_port) or isfile(args.lst_egress_dest_port)):
        if isfile(args.lst_ingress_orig_dest_port):
            INPUT_FILES['ingress']['file']=args.lst_ingress_orig_dest_port
            INPUT_FILES['ingress']['dest']=True
        elif isfile(args.lst_ingress_orig_port):
            INPUT_FILES['ingress']['file']=args.lst_ingress_orig_port
            INPUT_FILES['ingress']['dest']=False

        if isfile(args.lst_egress_orig_dest_port):
            INPUT_FILES['egress']['file']=args.lst_egress_orig_dest_port
            INPUT_FILES['egress']['dest']=True
        elif isfile(args.lst_egress_dest_port):
            INPUT_FILES['egress']['file']=args.lst_egress_dest_port
            INPUT_FILES['egress']['dest']=False

    else:
        print(' [%sERRO%s] Voce precisa especificar um arquivo de lista de regas.\n\n' % (color['red'],color['clean']))
        sys.exit(1)

    # -----------------------------------------------------------------------------
    # Carrega o arquivo de configuracao do oci cli para ter acesso ao OCI:
    auth_method=None
    if args.config != None:
        
        # https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clienvironmentvariables.htm
        oci_config = oci.config.from_file(args.config, 'DEFAULT')
        TENANCY_OCID = oci_config['tenancy']
        auth_method="Config File"

    # -----------------------------------------------------------------------------
    # Verifica se a variavel de ambiente do OCI CLI foi criada
    elif os.getenv('OCI_CLI_CONFIG_FILE'):
        oci_config_file = os.environ["OCI_CLI_CONFIG_FILE"]
        if isfile(oci_config_file):
            # https://docs.oracle.com/en-us/iaas/Content/API/SDKDocs/clienvironmentvariables.htm
            oci_config = oci.config.from_file(oci_config_file, 'DEFAULT')
            TENANCY_OCID = oci_config['tenancy']
            auth_method="Config File"

    else:
        try:
            if bool(os.environ["OCI_CLI_CLOUD_SHELL"]) == True:
                DELEGATION_TOKEN_FILE=os.environ["OCI_DELEGATION_TOKEN_FILE"]
                TENANCY_OCID = os.environ["OCI_TENANCY"]

                # get the cloud shell delegated authentication token
                delegation_token=open(DELEGATION_TOKEN_FILE, 'r').read() # create the api request signer
                signer = oci.auth.signers.InstancePrincipalsDelegationTokenSigner(
                    delegation_token=delegation_token
                )
                auth_method="Delegation Token"
            else:
                # By default this will hit the auth service in the region returned by
                # http://169.254.169.254/opc/v2/instance/region on the instance.
                ### signer = oci.auth.signers.InstancePrincipalsSecurityTokenSigner()
                print(" [ERRO] Instance Principal Autentication:Não implementado")
                auth_method="Instance Principal"

            # -----------------------------------------------------------------------------
            # Prepara o dicionario de configuracao com o signer
            oci_config = {'region':signer.region, 'tenancy':TENANCY_OCID}

        except Exception:
            print("*****************************************")
            print("* Error obtaining oci delegation token. *")
            print("* Aboting.                              *")
            print("*****************************************")
            print("")
            raise SystemExit

    # -------------------------------------------------------------------------
    # Cria o(s) objecto(s) de comunicacao com o OCI:
    if auth_method == "Config File":
        VirtualNetwork_Client = oci.core.VirtualNetworkClient(config=oci_config, retry_strategy=CUSTOM_RETRY_STRATEGY)
    elif auth_method == "Delegation Token":
        VirtualNetwork_Client = oci.core.VirtualNetworkClient(config=oci_config, signer=signer, retry_strategy=CUSTOM_RETRY_STRATEGY)
    else:
        exit(2)

    # -------------------------------------------------------------------------
    # Coleta as informacoes da NSG que esta sendo utilizada como target, ou seja,
    # onde sera adicionada as novas regras:
    nsg_info=get_nsg_info(VirtualNetwork_Client, args.nsg_ocid)
    if nsg_info['rules_count'] >= RULES_LIMIT:
        print("\n [%sERRO%s] O limit de \"120\" regras na NSG %s%s%s foi alcançado. Mais informação no link abaixo:" % (
            color['red'],color['clean'],color['red_blink'],nsg_info['name'],color['clean']
        ))
        print(" https://docs.oracle.com/en-us/iaas/Content/General/Concepts/servicelimits.htm#nsg_limits\n\n")
        sys.exit(2)

    # -------------------------------------------------------------------------
    # Lista todas as regras Ingress/Egress da lista de NSGs passadas por
    # parametro, para validacao de regras ja implantadas no ambiente.
    args.nsg_ocid_list.append(args.nsg_ocid)
    nsg_exist_rules=get_nsg_rules(VirtualNetwork_Client, args.nsg_ocid_list)

    # -----------------------------------------------------------------------------
    # Resumo da configuracao que esta sendo usada nessa execusao:
    print('\n >>> Resumo de configuração do script <<<')
    print('     |-> Mode de Autenticação: %s' % (auth_method))
    print('     |-> Arq. regras Ingress : %s' % (INPUT_FILES['ingress']['file']))
    print('     |-> Arq. regras Egress .: %s' % (INPUT_FILES['egress']['file']))
    print('     |-> NSG Nome ...........: %s' % (nsg_info['name']))
    print('     |   |-> OCID ...........: %s' % (args.nsg_ocid))
    print('     |   `-> Ingress/Egress..: %s' % (nsg_info['rules_count']))
    print('     `-> Lista de NSGs ......: (%s) ocids\n' % (len(args.nsg_ocid_list)))

    # -------------------------------------------------------------------------
    # Carrega o arquivo de regras e monta cada regra individualmente, 
    # quebrando os ranges de enderecos e porta:
    print(" >>> Carregando as linhas do arquivo de regras:")
    firewall_rules={'ingress':list(),'egress':list()}
    invalid_lines=valid_lines=comment_or_empty=address_invalid=0
    for rule_direction in INPUT_FILES:
        if INPUT_FILES[rule_direction]['file'] != None:
            with open(INPUT_FILES[rule_direction]['file']) as input_data:
                for line in input_data:
                    if re.findall('(^#)|(^$)', line):
                        comment_or_empty+=1
                    else:
                        line = line.strip()
                        line = (re.sub(r";$", "", line))
                        rows = line.split(' ')
                        # -----------------------------------------------------
                        # Retorna uma array com o(s) endereco(s) de origem e um
                        # boolean confirmando se o endereco é valido ou nao:
                        orig, ipv4_status = make_ipv4_address_list(str(rows[0]).strip())
                        if ipv4_status:
                            # -------------------------------------------------
                            # Monta a variavel PORT(a) com base no
                            # tipo do arquivo especificado para imput:
                            if INPUT_FILES[rule_direction]['dest']:
                                if len(rows) == 3:
                                    valid_lines+=1
                                    port = rows[2]
                                else:
                                    print('[ERRO](orig-dest-port) %s: %s' % (rule_direction,rows))
                                    invalid_lines += 1
                                    continue
                            else:
                                if len(rows) == 2:
                                    valid_lines+=1
                                    port = rows[1]
                                else:
                                    print('[ERRO](orig-port) %s: %s' % (rule_direction,rows))
                                    invalid_lines += 1
                                    continue

                            # -------------------------------------------------
                            # Guarda as regras com seus malores processados e 
                            # prontos para criacao dos objetos OCI
                            if rule_direction == 'ingress':
                                firewall_rules[rule_direction].append({
                                    'source':orig,
                                    'port':port.split(';')
                                })
                            elif rule_direction == 'egress':
                                firewall_rules[rule_direction].append({
                                    'destination':orig,
                                    'port':port.split(';')
                                })

                        else:
                            print('[ERRO] Endereco invalido: %s' % str(rows[0]).strip())
                            address_invalid+=1
                input_data.close()

    # Resumo de processamento:
    print("     |-> Processadas com sucesso.: %s" % (valid_lines))
    print("     |-> Comentários ou em branco: %s" % (comment_or_empty))
    print("     |-> Endereçamento inválido..: %s" % (address_invalid))
    if invalid_lines > 0:
        print("     `-> Processadas com Falha...: %s" % (invalid_lines))
        print("         `> Verifique o arquivo de regras.\n")
        print("   Exit...\n\n")
        sys.exit(1)
    else:
        print("     `-> Processadas com Falha...: %s\n" % (invalid_lines))

    # ---------------------------------------------------------------------
    # Cria o objetos de configuracao da security list para cada
    # linha de regra identificada no step anterior:
    print(" >>> Criando objetos de configuracao para cada rule:")
    count_rules={'ingress':0,'egress':0}
    nsg_new_rules={'ingress':list(),'egress':list()}
    for rule_direction in firewall_rules:
        # ---------------------------------------------------------------------
        if rule_direction == 'ingress':
            for rule in firewall_rules[rule_direction]:
                for source in rule['source']:
                    for port in rule['port']:
                        port_data = port.split('/')

                        # -----------------------------------------------------
                        # Identifica quais sao as portas necessarias para 
                        # liberacao da regra
                        if re.match('^(\d{1,5})$', port_data[1]):
                            port_min = port_max = port_data[1]
                        elif re.match('^(\d{1,5}\-\d{1,5})$', port_data[1]):
                            port_min, port_max = port_data[1].split('-')

                        # -----------------------------------------------------
                        # Monta o objeto do tipo TCP-Option para a criacao da 
                        # regra, por protocolo (TCP/UDP):
                        if (port_data[0]).upper() == 'UDP':
                            tcp_options=None
                            udp_options=oci.core.models.UdpOptions(
                                destination_port_range=oci.core.models.PortRange(
                                    max=int(port_max),
                                    min=int(port_min)
                                )
                            )
                        elif (port_data[0]).upper() == 'TCP':
                            udp_options=None
                            tcp_options=oci.core.models.TcpOptions(
                                destination_port_range=oci.core.models.PortRange(
                                    max=int(port_max),
                                    min=int(port_min)
                                )
                            )

                        # -----------------------------------------------------
                        # Monta o objecto da regra:
                        nsg_new_rules[rule_direction].append(
                            oci.core.models.AddSecurityRuleDetails(
                                description=args.rule_description,
                                direction=oci.core.models.AddSecurityRuleDetails.DIRECTION_INGRESS,
                                source_type=oci.core.models.AddSecurityRuleDetails.DESTINATION_TYPE_CIDR_BLOCK,
                                source=str(source),
                                is_stateless=False,
                                protocol=str(SECURITY_LIST_PROTOCOL[(port_data[0]).upper()]),
                                icmp_options=None,
                                tcp_options=tcp_options,
                                udp_options=udp_options
                            )
                        )
                        count_rules[rule_direction]+=1

        # ---------------------------------------------------------------------
        elif rule_direction == 'egress':
            for rule in firewall_rules[rule_direction]:
                for destination in rule['destination']:
                    for port in rule['port']:
                        port_data = port.split('/')

                        # -----------------------------------------------------
                        # Identifica quais sao as portas necessarias para 
                        # liberacao da regra
                        if re.match('^(\d{1,5})$', port_data[1]):
                            port_min = port_max = port_data[1]
                        elif re.match('^(\d{1,5}\-\d{1,5})$', port_data[1]):
                            port_min, port_max = port_data[1].split('-')

                        # -----------------------------------------------------
                        # Monta o objeto do tipo TCP-Option para a criacao da 
                        # regra, por protocolo (TCP/UDP):
                        if (port_data[0]).upper() == 'UDP':
                            tcp_options=None
                            udp_options=oci.core.models.UdpOptions(
                                destination_port_range=oci.core.models.PortRange(
                                    max=int(port_max),
                                    min=int(port_min)
                                )
                            )
                        elif (port_data[0]).upper() == 'TCP':
                            udp_options=None
                            tcp_options=oci.core.models.TcpOptions(
                                destination_port_range=oci.core.models.PortRange(
                                    max=int(port_max),
                                    min=int(port_min)
                                )
                            )

                        # -----------------------------------------------------
                        # Monta o objecto da regra:
                        nsg_new_rules[rule_direction].append(
                            oci.core.models.AddSecurityRuleDetails(
                                direction=oci.core.models.AddSecurityRuleDetails.DIRECTION_EGRESS,
                                destination_type=oci.core.models.AddSecurityRuleDetails.DESTINATION_TYPE_CIDR_BLOCK,
                                tcp_options=tcp_options,
                                udp_options=udp_options,
                                icmp_options=None,
                                is_stateless=False,
                                protocol=str(SECURITY_LIST_PROTOCOL[(port_data[0]).upper()]),
                                description=args.rule_description,
                                destination=str(destination),
                            )
                        )
                        count_rules[rule_direction]+=1
    print("     `-> Quantidade de regras por sentido de liberacao:")
    print("         |-> Egress.:%s" % (count_rules['egress']))
    print("         `-> Ingress:%s\n" % (count_rules['ingress']))

    print(" [INFO] *-> NSG: %s%s%s " % (color['red_blink'],nsg_info['name'],color['clean']))
    
    # -------------------------------------------------------------
    # Contabilizacao geral das regras:
    count_rules={'ingress':dict(),'egress':dict()}
    TOTAL_RULE={'deploy':0,'exist':dict(),'new':dict(),'duplicated':dict()}
    for rule_direction in rule_directions:
        TOTAL_RULE['exist'][rule_direction]=0
        TOTAL_RULE['new'][rule_direction]=0
        TOTAL_RULE['duplicated'][rule_direction]=0
        del(rule_direction)

    # -------------------------------------------------------------
    # Contabiliza as regras existentes para implementacao:
    print(" [INFO] |-> Verificando se existem regras duplicadas...")
    for rule_direction in ['ingress','egress']:
        count_rules[rule_direction]['before']=len(nsg_new_rules.get(rule_direction, list()))
        print(' [INFO] |   `-> %s:%s' % (rule_direction, count_rules[rule_direction]['before']))

        # -------------------------------------------------------------
        # Verifica a duplicidade entre as novas regras:
        if len(nsg_new_rules.get(rule_direction, list())):
            nsg_new_rules[rule_direction]=check_duplicate_rules(
                nsg_new_rules[rule_direction]
            )

        # -------------------------------------------------------------
        # Sumarizacao do processo de remocao das regras duplicadas:
        count_rules[rule_direction]['after']=len(nsg_new_rules.get(rule_direction, list()))
        if (count_rules[rule_direction]['after'] != count_rules[rule_direction]['before']):
            TOTAL_RULE['duplicated'][rule_direction]+=(count_rules[rule_direction]['before'] - count_rules[rule_direction]['after'])
            print(" [%sWARN%s] |       `-> %sAs regras duplicadas foram removidas da lista%s." % (
                color['yellow'],color['clean'],color['yellow'],color['clean']
            ))
        else:
            print(" [ %sOK%s ] |       `-> Nenhuma regra duplicada." % (color['green'],color['clean']))

    # -------------------------------------------------------------
    # Verifica se alguma das regras novas, ja esta aplicada no 
    # ambiente em alguma das NSGs que foram analisadas.
    print(" [INFO] |-> Verificando regras pre-existem...")

    for rule_direction in rule_directions:
        if len(nsg_exist_rules[rule_direction]) > 0:
            print(" [INFO] |   `-> %s:%s" % (
                rule_direction,
                len(nsg_exist_rules[rule_direction])
            ))
            # -----------------------------------------------------
            # Verifica se existem regras EGRESS pre-existente:
            if len(nsg_exist_rules[rule_direction]) > 0:
                if len(nsg_new_rules.get(rule_direction, list())) > 0:
                    BEFORE=len(nsg_new_rules.get(rule_direction, list()))
                    nsg_new_rules[rule_direction]=check_exist_rules(
                        nsg_new_rules[rule_direction],  # Nova regras
                        nsg_exist_rules[rule_direction] # Regras existentes na SecList
                    )
                    AFTER=len(nsg_new_rules.get(rule_direction, list()))
                    TOTAL_RULE['new'][rule_direction]+=len(nsg_new_rules.get(rule_direction, list()))
                    TOTAL_RULE['exist'][rule_direction]+=(BEFORE-AFTER)
        del(rule_direction)

    # ---------------------------------------------------------
    # Contabiliza as regras existentes + as novas:
    DEPLOY_COUNT=nsg_info['rules_count']
    for rule_direction in rule_directions:
        DEPLOY_COUNT+=TOTAL_RULE['new'][rule_direction]
        del(rule_direction)

    # ---------------------------------------------------------
    # Inicia as validacoes para adiciona as novas regras a NSG:
    RULES_TO_DEPLOY=list()

    # ---------------------------------------------------------
    # Valida a regra de implementacao ativa:
    RULES_COUNT_REMAIN=(RULES_LIMIT-nsg_info['rules_count'])
    if args.all_in:
        if (DEPLOY_COUNT < RULES_COUNT_REMAIN):
            for rule_direction in rule_directions:
                RULES_TO_DEPLOY.extend(nsg_new_rules.get(rule_direction, list()))
                del(rule_direction)

        else:
            print(" [%sERRO%s] |-> Não é possivel colocar %sTODAS AS REGRAS%s solicitadas (%s rules) nessa NSG." % (
                color['red'], color['clean'],color['red_blink'],color['clean'],DEPLOY_COUNT)
            )
            print(" [%sERRO%s] |   `-> So existe lugar para +(%s) regras na NSG (%s)" % (
                color['red'],color['clean'],
                RULES_COUNT_REMAIN,
                nsg_info['name']
            ))
    else:
        if (DEPLOY_COUNT < RULES_COUNT_REMAIN):
            for rule_direction in rule_directions:
                RULES_TO_DEPLOY.extend(nsg_new_rules.get(rule_direction, list()))
                del(rule_direction)

        else:
            TOTAL_COUNT=dict()
            for rule_direction in rule_directions:
                TOTAL_COUNT[rule_direction]=len(nsg_new_rules.get(rule_direction, list()))
                SELECTED_RULES=list()
                if TOTAL_COUNT[rule_direction] > 0:
                    # -------------------------------------------------------------
                    # Verifica se existem regras disponiveis no sentido
                    # que esta sendo processado para ser colocado na 
                    # lista de regras para deploy no ambiente:
                    if len(nsg_new_rules[rule_direction]) > 0:
                        for rule in nsg_new_rules[rule_direction]:
                            if (len(RULES_TO_DEPLOY)+len(SELECTED_RULES)) == RULES_COUNT_REMAIN:
                                print(' [%sWARN%s] |-> Não foi possivel implantar todas as regras solicitadas.' % (color['yellow'],color['clean']))
                                print(' [%sWARN%s] |   `-> %s%s%s:%s implantadas de %s regras no total.' % (
                                    color['yellow'],color['clean'],
                                    color['red'],rule_direction.upper(),color['clean'],
                                    len(SELECTED_RULES),
                                    TOTAL_COUNT[rule_direction]
                                ))
                                break
                            else:
                                SELECTED_RULES.append(rule)
                RULES_TO_DEPLOY.extend(SELECTED_RULES)
            del(rule_direction)


    # -------------------------------------------------------------------------
    # Faz o deploy das regra no ambiente:
    if (len(RULES_TO_DEPLOY) and (args.dry_run == False)) > 0:
        print(" [INFO] `-> Adicionando (%s) nova(s) regra(s)..." % (len(RULES_TO_DEPLOY)))
        TOTAL_RULE['deploy']=len(RULES_TO_DEPLOY)
        LAST_STATUS=None
        while len(RULES_TO_DEPLOY) > 0:
            # -----------------------------------------------------------------
            # A adicao de regras na NSG so pode ser feita de 25 em 25 regras.
            ADD_RULES=list()
            for i in range(25):
                if(len(RULES_TO_DEPLOY)) > 0:
                    ADD_RULES.append(RULES_TO_DEPLOY.pop())
                else:
                    break
            # -----------------------------------------------------------------
            # Adiciona as regras a NSG:
            add_nsg_rules_resp = VirtualNetwork_Client.add_network_security_group_security_rules(
                network_security_group_id=args.nsg_ocid,
                add_network_security_group_security_rules_details=oci.core.models.AddNetworkSecurityGroupSecurityRulesDetails(
                    security_rules=ADD_RULES
                )
            )

            LAST_STATUS=add_nsg_rules_resp.status
            if LAST_STATUS != 200:
                print(" [%sERRO%s]     `-> Falha ao atualizar a NSG (Status:%s)." % (color['red'],color['clean'],LAST_STATUS))

        if LAST_STATUS == 200:
            print(" [ %sOK%s ]     `-> NSG Atualizado com sucesso." % (color['green'],color['clean']))

    else:
        if args.dry_run:
            print(" [%sWARN%s] `-> Parametro %sDRY-RUN%s ativo, nenhuma regra foi impementada. ¯\_(ツ)_/¯" % (
                color['yellow'], color['clean'],color['red_blink'], color['clean']
            ))
        else:
            print(" [%sWARN%s] `-> Não existem regras para serem inseridas na NSG." % (
                color['yellow'], color['clean']
            ))

    print("\n\n")
    print("  +-------------------------------------------------+")
    print("  |            >>> Sumario da execusao <<<          |")
    print("  +------------------------+------------------------+")
    print("  |     INGRESS RULES      |      EGRESS RULES      |")
    print("  +------------------------+------------------------+")
    print("  | |-> Novas regras.: %03d | |-> Novas regras.: %03d |" % (TOTAL_RULE['new']['ingress'], TOTAL_RULE['new']['egress']))
    print("  | |-> Duplicadas...: %03d | |-> Duplicadas...: %03d |" % (TOTAL_RULE['duplicated']['ingress'], TOTAL_RULE['duplicated']['egress']))
    print("  | `-> Existentes...: %03d | `-> Existentes...: %03d |" % (TOTAL_RULE['exist']['ingress'], TOTAL_RULE['exist']['egress']))
    print("  +------------------------+------------------------+")
    print("  | Total de reglas implantadas(Ingress/Egress):%s%03d%s |" % (color['red'],TOTAL_RULE['deploy'],color['clean']))
    print("  +------------------------+------------------------+")
    print('\n   Terminado!\n    (-̀ᴗ-́)و ̑̑\n')
