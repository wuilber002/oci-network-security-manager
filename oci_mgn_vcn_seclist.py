#!/bin/env python
# =============================================================================================
# python oci_manage_security_list.py --security-list-ocid ocid1.securitylist.oc1.sa-saopaulo-1.aaaaaaaak2h65iqyybkuguhrmxeug6joof3c2mwrlk3psguilpnxdtjdx2fq
# =============================================================================================

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
# Prefixo para o nome da security list que sera usada pelo script para 
# implementar as regras de seguranca na Subnet/VCN:
SECURITY_LIST_PREFIX='SecList By Script'

# -----------------------------------------------------------------------------
# Regex para identificar ipv4
REGEX_IPV4 = re.compile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
REGEX_IPV4_ONLY = re.compile("^"+REGEX_IPV4.pattern+"$")
REGEX_IPV4_CIDR = re.compile("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\/(3[0-2]|[1-2]?\d)$")
REGEX_IPV4_RANGE = re.compile(REGEX_IPV4.pattern + '-' +REGEX_IPV4.pattern)

# -----------------------------------------------------------------------------
# Lista de protocolos para utilizacao na security lista, traduzindo-o para o
# codigo numerico correlato:
# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
SECURITY_LIST_PROTOCOL={'TCP':6,'UDP':17,6:"TCP",17:"UDP"}

# -----------------------------------------------------------------------------
# Limite de quantidade de regras em uma security lista
SECURITY_LIST_LIMIT={'INGRESS':200,'EGRESS':200}

# -----------------------------------------------------------------------------
# lista de cores para output do script:
color = {
    'yellow':'\033[33m',
    'green':'\033[32m',
    'blue':'\033[34m',
    'red':'\033[31m',
    'purple':'\033[35m' ,
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
def make_ipv4_address_list(ipv4_string):
    """
    """
    ipv4_to_return=list()
    # Processa o block de origem:
    if re.match(REGEX_IPV4_ONLY, ipv4_string):
        ipv4_to_return.append('%s/32' % str(ipv4_string))
        ipv4_type=1

    elif re.match(REGEX_IPV4_RANGE, ipv4_string):
        ip_range = ipv4_string.split('-')
        start_ip = ipaddress.IPv4Address(ip_range[0])
        end_ip = ipaddress.IPv4Address(ip_range[1])
        for ip_int in range(int(start_ip), int(end_ip)):
            ipv4_to_return.append('%s/32' % str(ipaddress.IPv4Address(ip_int)))
        ipv4_to_return.append('%s/32' % ip_range[1])
        ipv4_type=2

    elif re.match(REGEX_IPV4_CIDR, ipv4_string):
        for ip_int in ipaddress.IPv4Network(ipv4_string):
            ipv4_to_return.append(str(ipaddress.IPv4Address(ip_int)))
        ipv4_type=3

    else:
        print('Sei la o que eh isso:[%s]' % ipv4_string)

    return(ipv4_to_return,ipv4_type)

# -----------------------------------------------------------------------------
def get_subnet(vnet_client, vcn_ocid, subnet_compartment):

    # -------------------------------------------------------------------------
    # Consulta o Compartmento em que a VCN esta criada:
    # Se o valor recebido para o compartimento for "None" quer dizer que ele nao
    # foi especificado pelo usuario e sera necessario utilizar o compartimento
    # da VCN como comparimento padrao para pesquisa das subnets e subsequentes
    # acoes que precisam do parametro compartment.
    if subnet_compartment == None:
        vcn_resp = vnet_client.get_vcn(vcn_id=vcn_ocid)
        subnet_compartment=vcn_resp.data.compartment_id
        vcn_name=vcn_resp.data.display_name
        args.compartment_ocid = subnet_compartment

    # -------------------------------------------------------------------------
    # Lista todas as subnets ligadas a VCN que se encontram
    # no compartimento:
    subnets_resp = vnet_client.list_subnets(
        compartment_id=subnet_compartment,
        vcn_id=vcn_ocid,
    )

    # -------------------------------------------------------------------------
    # Inicia o processo para localizar as subnets da VCN:
    subnet_list=dict()
    for subnet in subnets_resp.data:
        subnet_list[subnet.cidr_block]={
            'id':str(subnet.id), # OCID da SubNet
            'display_name':str(subnet.display_name), # Nome da SubNet
            "rules":{"ingress":[],"egress":[]}, # lista de todas as regras em todas as seclists da subnet
            'security_list':list() # Lista das seclists que possuem a tag liberando seu uso pelo script
        }
        for subnet_list_id in subnet.security_list_ids:
            subnet_list_resp = (vnet_client.get_security_list(security_list_id=subnet_list_id)).data

            # -----------------------------------------------------------------
            # Guarda todas as regras da subnet para validacao de regras ja 
            # implementadas no ambiente e evitar duplicidade de regras.
            for egress in subnet_list_resp.egress_security_rules:
                subnet_list[subnet.cidr_block]['rules']['egress'].append(egress)
            for ingress in subnet_list_resp.ingress_security_rules:
                subnet_list[subnet.cidr_block]['rules']['ingress'].append(ingress)

            # -----------------------------------------------------------------
            # Verifica se a security lista que esta sendo analizada possui a
            # tag de liberacao de uso para o script:
            if "AllowAutomation" in subnet_list_resp.freeform_tags:
                if subnet_list_resp.freeform_tags['AllowAutomation'] == "ScriptEdition":
                    subnet_list[subnet.cidr_block]['security_list'].append({
                        'id':subnet_list_id,
                        'display_name':subnet_list_resp.display_name,
                        'ingress':len(subnet_list_resp.ingress_security_rules),
                        'egress':len(subnet_list_resp.egress_security_rules)
                    })
    return(vcn_name, subnet_list)

# -----------------------------------------------------------------------------
### def create_security_list(vnet_client, vcn_id, compartment_id, subnet_list_name, new_rules, ingress_rules):
###     security_list_details= oci.core.models.CreateSecurityListDetails(
###         compartment_id=compartment_id,
###         egress=new_rules,
###         ingress=ingress_rules,
###         vcn_id=vcn_id,
###         display_name=subnet_list_name,
###     )
###     return((vnet_client.create_security_list(
###         create_security_list_details=security_list_details
###     )))

# -----------------------------------------------------------------------------
### def add_security_list_to_subnet(vnet_client, subnet_id, subnet_list_ids):
###     update_subnet_response = vnet_client.update_subnet(
###         subnet_id=subnet_id,
###         update_subnet_details=oci.core.models.UpdateSubnetDetails(
###             security_list_ids=subnet_list_ids
###         ),
###     )
### 
###     # Get the data from response
###     return(update_subnet_response.status)

# -----------------------------------------------------------------------------
def check_duplicate_rules(rules, cidr, root_identation):
    DDUP_RULES=list()

    # -------------------------------------------------
    if root_identation:
        root_ident="|"
    else:
        root_ident=" "

    # -------------------------------------------------
    # Lista as novas regras para serem adicionadas a subnet_list:
    for protocol in ['tcp', 'udp']:
        count_rule=0
        proto_option=('%s_options' % protocol)
        for rule in rules:
            count_rule+=1
            # -----------------------------------------------------------------
            # invoca attributos de forma customizada, conforme o
            # protocolo ou o sentido da regra INGRESS/EGRESS:
            rule_options=getattr(rule, proto_option)
            if isinstance(rule, oci.core.models.ingress_security_rule.IngressSecurityRule):
                rule_type='INGRESS'
                target_name='orig'
                cidr_name='dest'
                rule_target=rule.source
            elif isinstance(rule, oci.core.models.egress_security_rule.EgressSecurityRule):
                rule_type='EGRESS'
                target_name='dest'
                cidr_name='orig'
                rule_target=rule.destination

            RULE_FOUND=False
            if rule_options == None:
                continue
            # Lista as regras existentes na subnet_list:
            for copy_rule in DDUP_RULES:

                # -----------------------------------------------------------------
                # invoca attributos de forma customizada, conforme o
                # protocolo ou o sentido da regra INGRESS/EGRESS:
                copy_rule_options=getattr(copy_rule, proto_option)
                if isinstance(rule, oci.core.models.ingress_security_rule.IngressSecurityRule):
                    copy_rule_target=copy_rule.source
                elif isinstance(rule, oci.core.models.egress_security_rule.EgressSecurityRule):
                    copy_rule_target=copy_rule.destination

                if copy_rule_options == None:
                    continue
                if (rule_target == copy_rule_target and
                    rule.protocol == copy_rule.protocol and
                    rule_options.destination_port_range.min == copy_rule_options.destination_port_range.min and
                    rule_options.destination_port_range.max == copy_rule_options.destination_port_range.max):
                        RULE_FOUND=True
                        if rule_options.destination_port_range.min == rule_options.destination_port_range.max:
                            port=rule_options.destination_port_range.max
                        else:
                            port=('%s-%s' % (
                                rule_options.destination_port_range.min,
                                rule_options.destination_port_range.max
                            ))
                        
                        print(" [%sWARN%s] %s   |   |-> (%03d) %sDUPLICATED %s RULE%s - %s:%s, %s:%s, port:%s/%s" % (
                            color['yellow'],color['clean'],root_ident,count_rule,color['yellow'],rule_type,color['clean'],
                            cidr_name,cidr,target_name,rule_target,SECURITY_LIST_PROTOCOL[int(copy_rule.protocol)],port
                        ))
                        break
            if RULE_FOUND == False:
                DDUP_RULES.append(rule)

    return(DDUP_RULES)

# -----------------------------------------------------------------------------
def check_exist_rules(new_rules, old_rules, cidr, root_identation):
    # -------------------------------------------------
    # Lista as novas regras para serem adicionadas a subnet_list:
    NEW_RULES=list()

    # -------------------------------------------------
    if root_identation:
        root_ident="|"
    else:
        root_ident=" "

    for protocol in ['tcp', 'udp']:
        proto_option=('%s_options' % protocol)
        count_rule=0
        for new_rule in new_rules:
            count_rule+=1
            # -----------------------------------------------------------------
            # invoca attributos de forma customizada, conforme o
            # protocolo ou o sentido da regra INGRESS/EGRESS:
            rule_options=getattr(new_rule, proto_option)
            if isinstance(new_rule, oci.core.models.ingress_security_rule.IngressSecurityRule):
                rule_target=new_rule.source
                identention=' '
                target_name='orig'
                cidr_name='dest'
            elif isinstance(new_rule, oci.core.models.egress_security_rule.EgressSecurityRule):
                rule_target=new_rule.destination
                identention='|'
                target_name='dest'
                cidr_name='orig'

            RULE_FOUND=False
            if rule_options == None:
                continue
            # Lista as regras existentes na subnet_list:
            for old_rule in old_rules:

                # -----------------------------------------------------------------
                # invoca attributos de forma customizada, conforme o
                # protocolo ou o sentido da regra INGRESS/EGRESS:
                old_rule_options=getattr(old_rule, proto_option)
                if isinstance(new_rule, oci.core.models.ingress_security_rule.IngressSecurityRule):
                    old_rule_target=old_rule.source
                elif isinstance(new_rule, oci.core.models.egress_security_rule.EgressSecurityRule):
                    old_rule_target=old_rule.destination

                if old_rule_options == None:
                    continue
                if (rule_target == old_rule_target and
                    new_rule.protocol == old_rule.protocol and
                    rule_options.destination_port_range.min == old_rule_options.destination_port_range.min and
                    rule_options.destination_port_range.max == old_rule_options.destination_port_range.max):
                        RULE_FOUND=True
                        if rule_options.destination_port_range.min == rule_options.destination_port_range.max:
                            port=rule_options.destination_port_range.max
                        else:
                            port=('%s-%s' % (
                                rule_options.destination_port_range.min,
                                rule_options.destination_port_range.max
                            ))
                        if count_rule == len(new_rules):
                            print(" [%sWARN%s] %s   %s   `-> [%03d] %sEXIST%s - %s:%s, %s:%s, port:%s/%s" % (
                                color['yellow'],color['clean'],root_ident,identention,count_rule,color['yellow'],color['clean'],
                                cidr_name,cidr,target_name,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                            ))
                        else:
                            print(" [%sWARN%s] %s   %s   |-> [%03d] %sEXIST%s - %s:%s, %s:%s, port:%s/%s" % (
                                color['yellow'],color['clean'],root_ident,identention,count_rule,color['yellow'],color['clean'],
                                cidr_name,cidr,target_name,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                            ))
                        break
            if RULE_FOUND == False:
                NEW_RULES.append(new_rule)
                if rule_options.destination_port_range.min == rule_options.destination_port_range.max:
                    port=rule_options.destination_port_range.max
                else:
                    port=('%s-%s' % (
                        rule_options.destination_port_range.min,
                        rule_options.destination_port_range.max
                    ))
                if count_rule == len(new_rules):
                    print(" [ %sOK%s ] %s   |   `-> [%03d] %sN-E-W%s - %s:%s, %s:%s, port:%s/%s" % (
                        color['green'],color['clean'],root_ident,count_rule,color['green'],color['clean'],
                        cidr_name,cidr,target_name,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                    ))
                else:
                    print(" [ %sOK%s ] %s   |   |-> [%03d] %sN-E-W%s - %s:%s, %s:%s, port:%s/%s" % (
                        color['green'],color['clean'],root_ident,count_rule,color['green'],color['clean'],
                        cidr_name,cidr,target_name,rule_target,SECURITY_LIST_PROTOCOL[int(new_rule.protocol)],port
                    ))

    return(NEW_RULES)

# -----------------------------------------------------------------------------
def update_rules_in_seclist(vnet_client, seclist_id, rule_type, rules):
    
    if (rule_type).upper() == 'EGRESS':
        update_seclist_resp = vnet_client.update_security_list(
            security_list_id=seclist_id,
            update_security_list_details=oci.core.models.UpdateSecurityListDetails(
                    egress=rules,
                )
            )
    elif (rule_type).upper() == 'INGRESS':
        update_seclist_resp = vnet_client.update_security_list(
            security_list_id=seclist_id,
            update_security_list_details=oci.core.models.UpdateSecurityListDetails(
                ingress=rules,
            )
        )
    # Get the data from response
    return(update_seclist_resp.status)

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
    sys.stdout = Unbuffered(sys.stdout)

    # -----------------------------------------------------------------------------
    # Configuracao dos parametros do script:
    parser = ArgumentParser(
        allow_abbrev=False,
        formatter_class=ArgumentDefaultsHelpFormatter,
        description="Script de coleta de dados de performace (OPDR - Oracle Performance Data Report) e inventario de instaces em ambiente OCI.",
    )

    ### parser.add_argument('-m', '--metric', default='.metric_query', help="Arquivo com a lista de metricas que o script vai coletar durante sua execusao.")
    parser.add_argument('-f', '--rule-file', help="")
    parser.add_argument('-s', '--security-list-ocid', default=None, help="")
    parser.add_argument('-n', '--vcn-ocid', default=None, help="")
    parser.add_argument('-p', '--compartment-ocid', default=None, help="")
    parser.add_argument('-c', '--config', default=None, help="O metodo padrao de autenticacao eh Token Delegation (Choud Shell). Mas voce pode usar o arquivo de configuracao \"config\" do proprio \"oci cli\".")
    args = parser.parse_args()

    # -----------------------------------------------------------------------------
    # Verifica se o arquivo de regras existe:
    if args.rule_file:
        if not isfile(args.rule_file):
            print(' [%sERRO%s] O arquivo (%s) eh inválido ou nao foi encontrado.\n\n' % (
                color['red'],color['clean'],args.rule_file
            ))
            sys.exit(2)
    else:
        print(' [%sERRO%s] Voce precisa especificar um arquivo de regas.\n\n' % (color['red'],color['clean']))
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
                print(" [ERRO] Instance Principal Autentication:Nao implementado")
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

    # -----------------------------------------------------------------------------
    # Resumo da configuracao que esta sendo usada nessa execusao:
    print('\n >>> Resumo de configuração do script <<<')
    print('     |-> Mode de Autenticação: %s' % (auth_method))
    print('     |-> Arquivo de regras...: %s' % (args.rule_file))
    print('     |-> OCID da VCN.........: %s' % (args.vcn_ocid))
    print('     `-> OCID do Compartment.: %s\n' % (args.compartment_ocid))

    # -------------------------------------------------------------------------
    # Cria o(s) objecto(s) de comunicacao com o OCI:
    if auth_method == "Config File":
        VirtualNetwork_Client = oci.core.VirtualNetworkClient(config=oci_config, retry_strategy=CUSTOM_RETRY_STRATEGY)
    elif auth_method == "Delegation Token":
        VirtualNetwork_Client = oci.core.VirtualNetworkClient(config=oci_config, signer=signer, retry_strategy=CUSTOM_RETRY_STRATEGY)
    else:
        exit(2)

    # -------------------------------------------------------------------------
    # Contabilizacao de quantidade de rules implementadas pelo script:
    TOTAL_INGRESS_RULE_DEPLOED=0
    TOTAL_INGRESS_RULE_DUPLICATED=0
    TOTAL_INGRESS_RULE_EXIST=0
    TOTAL_EGRESS_RULE_DEPLOED=0
    TOTAL_EGRESS_RULE_DUPLICATED=0
    TOTAL_EGRESS_RULE_EXIST=0

    # -------------------------------------------------------------------------
    # Consulta a lista de subnets criadas na VCN, separando o seu nome, cidr e
    # varifica se a security list (especifica) para o uso do script existe:
    print(" >>> Carregando lista de SubNets da VCN:")
    vcn_name, subnet_list = get_subnet(VirtualNetwork_Client, args.vcn_ocid, args.compartment_ocid)
    print("     |-> VCN Name: %s" % (vcn_name))
    print("     `-> Quantidade de SubNets: %s" % (len(subnet_list)))

    for index, cidr in enumerate(subnet_list, start=1):
        if len(subnet_list[cidr]['security_list']) > 0:
            tag_allow_edit=("tag[%sScriptEdition%s]" % (color['green'],color['clean']))
            status=("[%s%s%s]" % (color['green'],index,color['clean']))
        else:
            tag_allow_edit=("- %sTag Not Found%s" % (color['yellow'],color['clean']))
            status=("[%s%s%s]" % (color['yellow'],index,color['clean']))

        if index == len(subnet_list):
            print("         `-> %s %s (%s) %s" % (status,subnet_list[cidr]['display_name'],cidr,tag_allow_edit))
            print("             `-> Egress.: %s, Ingress: %s\n" % (
                len(subnet_list[cidr]['rules']['egress']),
                len(subnet_list[cidr]['rules']['ingress'])
            ))
        else:
            print("         |-> %s %s (%s) %s" % (status,subnet_list[cidr]['display_name'],cidr,tag_allow_edit))
            print("         |   `-> Egress.: %s, Ingress: %s" % (
                len(subnet_list[cidr]['rules']['egress']),
                len(subnet_list[cidr]['rules']['ingress'])
            ))

    # -------------------------------------------------------------------------
    # Carrega o arquivo de regras e monta cada regra individualmente, 
    # quebrando os ranges de enderecos e porta:
    print(" >>> Carregando as linhas do arquivo de regras:")
    firewall_rules=list()
    with open(args.rule_file) as input_data:
        invalid_lines=valid_lines=comment_or_empty=address_not_found=0
        for line in input_data:
            rule_type=None
            if re.findall('(^#)|(^$)', line):
                comment_or_empty+=1
            else:
                line = line.strip()
                line = (re.sub(r";$", "", line))
                rows = line.split(' ')
                if len(rows) == 3:
                    if (rows[0] in subnet_list and rows[1] in subnet_list):
                        print("Os dois estao dentro da VCN.")
                        rule_type='ingress'
                        dest = str(rows[1]).strip()
                        orig, ipv4_type = make_ipv4_address_list(str(rows[0]).strip())
                    elif rows[0] in subnet_list:
                        rule_type='egress'
                        orig = str(rows[0]).strip()
                        dest, ipv4_type = make_ipv4_address_list(str(rows[1]).strip())
                    elif rows[1] in subnet_list:
                        rule_type='ingress'
                        dest = str(rows[1]).strip()
                        orig, ipv4_type = make_ipv4_address_list(str(rows[0]).strip())
                    else:
                        address_not_found+=1
                        _, ipv4_type0 = make_ipv4_address_list(str(rows[0]).strip())
                        _, ipv4_type1 = make_ipv4_address_list(str(rows[1]).strip())
                        if (ipv4_type0 == 1 and ipv4_type1 == 1 ):
                            print("     |-> [%sERRO%s] Libere essa regra com NSG: %s%s%s %s%s%s %s%s%s" % (
                                color['red'],color['clean'],color['red'],rows[0],color['clean'],color['purple'],
                                rows[1],color['clean'],color['blue'],rows[2],color['clean']
                            ))
                        else:
                            print("     |-> [%sERRO%s] Endereço desconhecido: %s%s%s %s%s%s" % (
                                color['red'],color['clean'],color['red'],rows[0],color['clean'],color['purple'],rows[1],color['clean']
                            ))
                        continue

                    firewall_rules.append({
                        'type':rule_type,
                        'orig':orig,
                        'dest':dest,
                        'port':rows[2].split(';')
                    })
                    valid_lines+=1
                else:
                    invalid_lines += 1

        input_data.close()
        print("     |-> Processadas com sucesso.: %s" % (valid_lines))
        print("     |-> Comentários ou em branco: %s" % (comment_or_empty))
        print("     |-> Endereçamento inválido..: %s" % (address_not_found))
        if invalid_lines > 0:
            print("     `-> Processadas com Falha...: %s" % (invalid_lines))
            print("         `> Verifique o arquivo (%s) de regras.\n\n" % (args.rule_file))
            sys.exit(1)
        else:
            print("     `-> Processadas com Falha...: %s\n" % (invalid_lines))

    # ---------------------------------------------------------------------
    # Cria o objetos de configuracao da security list para cada
    # linha de regra identificada no step anterior:
    print(" >>> Criando objetos de configuracao para cada rule:")
    count_rules={'INGRESS':0,'EGRESS':0}
    for rule in firewall_rules:
        if rule['type'] == 'ingress':
            if not 'rules' in subnet_list[rule['dest']]:
                subnet_list[rule['dest']]['rules']={'egress':list(),'ingress':list()}
            for orig in rule['orig']:
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
                    subnet_list[rule['dest']]['rules']['ingress'].append(
                        oci.core.models.IngressSecurityRule(
                            source=str(orig),
                            source_type="CIDR_BLOCK",
                            description="Regra criada por script",
                            protocol=str(SECURITY_LIST_PROTOCOL[(port_data[0]).upper()]),
                            is_stateless=False,
                            icmp_options=None,
                            tcp_options=tcp_options,
                            udp_options=udp_options
                        )
                    )
                    count_rules['INGRESS']+=1

        if rule['type'] == 'egress':
            if not 'rules' in subnet_list[rule['orig']]:
                subnet_list[rule['orig']]['rules']={'egress':list(),'ingress':list()}
            for dest in rule['dest']:
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
                    subnet_list[rule['orig']]['rules']['egress'].append(
                        oci.core.models.EgressSecurityRule(
                            destination=str(dest),
                            destination_type="CIDR_BLOCK",
                            description="Regra criada por script",
                            protocol=str(SECURITY_LIST_PROTOCOL[(port_data[0]).upper()]),
                            is_stateless=False,
                            icmp_options=None,
                            tcp_options=tcp_options,
                            udp_options=udp_options
                        )
                    )
                    count_rules['EGRESS']+=1
    print("     `-> Quantidade de regras por sentido de liberacao:")
    print("         |-> Egress.:%s" % (count_rules['EGRESS']))
    print("         `-> Ingress:%s\n" % (count_rules['INGRESS']))

    # ---------------------------------------------------------------------
    # Processa as regras montadas para identificar quais estao
    # duplicadas ou se ja estao implementadas no ambiente.
    CIDR_COUNT=0
    TOTAL_RULES=0
    for cidr in subnet_list:
        CIDR_COUNT+=1
        print(" [INFO] +-> %s [%s]" % (subnet_list[cidr]['display_name'], cidr))
        if 'rules' in subnet_list[cidr]:
            TOTAL_RULES+=(
                len(subnet_list[cidr]['rules'].get('egress', list())) +
                len(subnet_list[cidr]['rules'].get('ingress', list()))
            )

            # -------------------------------------------------------------
            # Controla a identacao das mensagens:
            if CIDR_COUNT == len(subnet_list):
                root_ident=False
            else:
                root_ident=True

            # -------------------------------------------------------------
            # Contabiliza as regras existentes para implementacao:
            count_egress={'after':0,'before':len(subnet_list[cidr]['rules'].get('egress', list()))}
            count_ingress={'after':0,'before':len(subnet_list[cidr]['rules'].get('ingress', list()))}
            if root_ident:
                print(" [INFO] |   |-> Verificando se existem regras duplicadas...")
                print(' [INFO] |   |   |-> Egress:%s, Ingress:%s' % (count_egress['before'], count_ingress['before']))
            else:
                print(" [INFO]     |-> Verificando se existem regras duplicadas...")
                print(' [INFO]     |   |-> Egress:%s, Ingress:%s' % (count_egress['before'], count_ingress['before']))

            # -------------------------------------------------------------
            # Verifica a duplicidade entre as novas regras:
            if len(subnet_list[cidr]['rules'].get('egress', list())):
                subnet_list[cidr]['rules']['egress']=check_duplicate_rules(
                    subnet_list[cidr]['rules'].get('egress', list()),
                    cidr,
                    root_ident
                )
            if len(subnet_list[cidr]['rules'].get('ingress', list())):
                subnet_list[cidr]['rules']['ingress']=check_duplicate_rules(
                    subnet_list[cidr]['rules'].get('ingress', list()),
                    cidr,
                    root_ident
                )

            # -------------------------------------------------------------
            # Re-contabiliza as regras existentes para implementacao:
            count_egress['after']=len(subnet_list[cidr]['rules'].get('egress', list()))
            count_ingress['after']=len(subnet_list[cidr]['rules'].get('ingress', list()))
            if ((count_egress['after'] != count_egress['before']) or
                (count_ingress['after'] != count_ingress['before'])):
                
                TOTAL_INGRESS_RULE_DUPLICATED+=(count_egress['before'] - count_egress['after'])
                TOTAL_EGRESS_RULE_DUPLICATED+=(count_ingress['before'] - count_ingress['after'])
                
                if root_ident:
                    print(" [%sWARN%s] |   |   `-> %sAs regras duplicadas foram removidas da lista%s." % (
                        color['yellow'],color['clean'],color['yellow'],color['clean']
                    ))
                else:
                    print(" [%sWARN%s]     |   `-> %sAs regras duplicadas foram removidas da lista%s." % (
                        color['yellow'],color['clean'],color['yellow'],color['clean']
                    ))
            else:
                print(" [ %sOK%s ] |   |   `-> Nenhuma regra duplicada." % (color['green'],color['clean']))

            # -------------------------------------------------------------
            # Verifica se existe security list disponivel para aplicar as
            # regras na VCN
            if len(subnet_list[cidr]['security_list']) == 0:
                if root_ident:
                    print(" [%sERRO%s] |   |   |-> Essa SubNet nao tem uma SecList liberada para uso." % (
                        color['red'],color['clean']
                    ))
                else:
                    print(" [%sERRO%s]    |   |-> Essa SubNet nao tem uma SecList liberada para uso." % (
                        color['red'],color['clean']
                    ))

            else:

                RULES_TO_DEPLOY={'INGRESS':list(),'EGRESS':list()}
                # ---------------------------------------------------------
                # Lista todas as subnet_lists elegiveis a utilizacao do script:
                for subnet in subnet_list[cidr]['security_list']:
                    if ( len(subnet['egress']) > 0 or len(subnet['ingress']) > 0):
                        if root_ident:
                            print(" [INFO] |   |-> Verificando regras pre-existem...")
                        else:
                            print(" [INFO]     |-> Verificando regras pre-existem...")

                    # -----------------------------------------------------
                    # Verifica se existem regras EGRESS pre-existente:
                    if len(subnet['egress']) > 0:
                        if root_ident:
                            if len(subnet['ingress']) > 0:
                                print(" [INFO] |   |-> Egress:%s" % (len(subnet['egress'])))
                            else:
                                print(" [INFO] |   `-> Egress:%s" % (len(subnet['egress'])))
                        else:
                            if len(subnet['ingress']) > 0:
                                print(" [INFO]     |-> Egress:%s" % (len(subnet['egress'])))
                            else:
                                print(" [INFO]     `-> Egress:%s" % (len(subnet['egress'])))

                        if len(subnet_list[cidr]['rules'].get('egress', list())) > 0:
                            NEW_RULES=check_exist_rules(
                                subnet_list[cidr]['rules'].get('egress', list()), # Nova regras
                                subnet['egress'], # Regras existentes na SecList
                                cidr,
                                root_ident
                            )
                            TOTAL_EGRESS_RULE_EXIST+=(len(subnet_list[cidr]['rules'].get('egress', list()))-len(NEW_RULES))
                            if len(NEW_RULES) > 0:
                                RULES_TO_DEPLOY['EGRESS'].extend(subnet['egress']) # Regras existentes na SecList
                                RULES_TO_DEPLOY['EGRESS'].extend(NEW_RULES) # Nova regras apos a validacao de duplicadas
                    else:
                        if len(subnet_list[cidr]['rules'].get('egress', list())) > 0:
                            RULES_TO_DEPLOY['EGRESS'].extend(subnet_list[cidr]['rules'].get('egress', list()))

                    # -----------------------------------------------------
                    # Verifica se existem regras INGRESS pre-existente:
                    if len(subnet['ingress']) > 0:
                        if root_ident:
                            print(" [INFO] |   `-> Ingress:%s" % (len(subnet['ingress'])))
                        else:
                            print(" [INFO]     `-> Ingress:%s" % (len(subnet['ingress'])))
                        if len(subnet_list[cidr]['rules'].get('ingress', list())) > 0:
                            NEW_RULES=check_exist_rules(
                                subnet_list[cidr]['rules'].get('ingress', list()), # Nova regras
                                subnet['ingress'], # Regras existentes na SecList
                                cidr,
                                root_ident
                            )
                            TOTAL_INGRESS_RULE_EXIST+=(len(subnet_list[cidr]['rules'].get('ingress', list()))-len(NEW_RULES))
                            if len(NEW_RULES) > 0:
                                RULES_TO_DEPLOY['INGRESS'].extend(subnet['ingress']) # Regras existentes na SecList
                                RULES_TO_DEPLOY['INGRESS'].extend(NEW_RULES) # Nova regras apos a validacao de duplicadas
                    else:
                        if len(subnet_list[cidr]['rules'].get('ingress', list())) > 0:
                            RULES_TO_DEPLOY['INGRESS'].extend(subnet_list[cidr]['rules'].get('ingress', list()))

                
                sys.exit(0)
                # ---------------------------------------------------------
                # Adiciona as novas regras 
                for subnet in subnet_list[cidr]['security_list']:
                    if (len(RULES_TO_DEPLOY['EGRESS']) > 0 or len(RULES_TO_DEPLOY['INGRESS']) > 0):
                        if root_ident:
                            print(" [INFO] |   |-> Adicionando nova regra...")
                        else:
                            print(" [INFO]     |-> Adicionando nova regra...")

                    if len(RULES_TO_DEPLOY['EGRESS']) > 0:
                        if root_ident:
                            if len(RULES_TO_DEPLOY['INGRESS']) > 0:
                                print(" [INFO] |   |-> Egress:%s" % (len(RULES_TO_DEPLOY['EGRESS'])))
                            else:
                                print(" [INFO] |   `-> Egress:%s" % (len(RULES_TO_DEPLOY['EGRESS'])))

                        else:
                            if len(RULES_TO_DEPLOY['INGRESS']) > 0:
                                print(" [INFO]     |-> Egress:%s" % (len(RULES_TO_DEPLOY['EGRESS'])))
                            else:
                                print(" [INFO]     `-> Egress:%s" % (len(RULES_TO_DEPLOY['EGRESS'])))

                        TOTAL_EGRESS_RULE_DEPLOED+=len(RULES_TO_DEPLOY['EGRESS'])
                        status_update_ingress_rule=update_rules_in_seclist(
                            VirtualNetwork_Client,subnet['id'],'EGRESS',RULES_TO_DEPLOY['EGRESS']
                        )
                        if status_update_ingress_rule == 200:
                            if root_ident:
                                print(" [ %sOK%s ] |       `-> Security Lists Atualizada com sucesso:%s%s%s." % (
                                    color['green'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))
                            else:
                                print(" [ %sOK%s ]         `-> Security Lists Atualizada com sucesso:%s%s%s." % (
                                    color['green'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))
                        else:
                            if root_ident:
                                print(" [%sERRO%s] |       `-> Falha ao atualizar a Security List:%s%s%s." % (
                                    color['red'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))
                            else:
                                print(" [%sERRO%s]         `-> Falha ao atualizar a Security List:%s%s%s." % (
                                    color['red'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))

                    if len(RULES_TO_DEPLOY['INGRESS']) > 0:
                        if root_ident:
                            print(" [INFO] |   `-> Ingress:%s" % (len(RULES_TO_DEPLOY['INGRESS'])))
                        else:
                            print(" [INFO]     `-> Ingress:%s" % (len(RULES_TO_DEPLOY['INGRESS'])))

                        TOTAL_INGRESS_RULE_DEPLOED+=len(RULES_TO_DEPLOY['INGRESS'])
                        status_update_egress_rule=update_rules_in_seclist(
                            VirtualNetwork_Client,subnet['id'],'INGRESS',RULES_TO_DEPLOY['INGRESS']
                        )
                        if status_update_egress_rule == 200:
                            if root_ident:
                                print(" [ %sOK%s ] |       `-> Security Lists Atualizada com sucesso:%s%s%s." % (
                                    color['green'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))
                            else:
                                print(" [ %sOK%s ]         `-> Security Lists Atualizada com sucesso:%s%s%s." % (
                                    color['green'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))
                        else:
                            if root_ident:
                                print(" [%sERRO%s] |       `-> Falha ao atualizar a Security List:%s%s%s." % (
                                    color['red'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))
                            else:
                                print(" [%sERRO%s]         `-> Falha ao atualizar a Security List:%s%s%s." % (
                                    color['red'],color['clean'],color['purple'],subnet['display_name'],color['clean']
                                ))

    print("\n\n")
    print("  +-------------------------------------------------+")
    print("  |            >>> Sumario da execusao <<<          |")
    print("  +------------------------+------------------------+")
    print("  |      INGRESS RULES     |       INGRESS RULES    |")
    print("  +------------------------+------------------------+")
    print("  | |-> implementadas: %03d | |-> implementadas: %03d |" % (TOTAL_INGRESS_RULE_DEPLOED, TOTAL_EGRESS_RULE_DEPLOED))
    print("  | |-> Duplicadas...: %03d | |-> Duplicadas...: %03d |" % (TOTAL_INGRESS_RULE_DUPLICATED, TOTAL_EGRESS_RULE_DUPLICATED))
    print("  | `-> Existentes...: %03d | `-> Existentes...: %03d |" % (TOTAL_INGRESS_RULE_EXIST, TOTAL_EGRESS_RULE_EXIST))
    print("  +------------------------+------------------------+")
    print("  | Total de regras (Ingress/Egress):%03d            |" % (TOTAL_RULES))
    print("  +------------------------+------------------------+")
    print('\n   Terminado!\n    (-̀ᴗ-́)و ̑̑\n')
