from configloader import load_config, get_config


def getKeys():
    key_list = ['id', 'port', 'passwd', 'enable']
    if get_config().API_INTERFACE == 'sspanelv3':
        key_list += ['method']
    elif get_config().API_INTERFACE == 'sspanelv3ssr':
        key_list += ['method', 'obfs', 'protocol']
    elif get_config().API_INTERFACE == 'glzjinmod':
        key_list += ['method',
                     'obfs',
                     'obfs_param',
                     'protocol',
                     'protocol_param',
                     'id',
                     'node_speedlimit',
                     'forbidden_ip',
                     'forbidden_port',
                     'disconnect_ip',
                     'is_multi_user']
    return key_list
    # return key_list + ['plan'] # append the column name 'plan'

def getPortGroupKeys():
    keys_dict = {}
    keys_dict['user'] = [
        'id', 'enable',
        'node_speedlimit',
        'forbidden_ip', 'forbidden_port', 'disconnect_ip',
        'is_multi_user'
    ]
    keys_dict['user_method'] = [
        'port', 'passwd', 'method',
        'protocol', 'protocol_param', 'obfs', 'obfs_param',
        'enable_dnsLog', 'node_speedlimit'
    ]
    return keys_dict

def isTurnOn(row):
    return True
    # return row['plan'] == 'B' # then judge here
