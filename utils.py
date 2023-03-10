def generate_dtype() -> dict:
    return {
        'id': 'int32',
        'dur': 'float64',
        'proto': 'object',
        'service': 'object',
        'state': 'object',
        'spkts': 'int32',
        'dpkts': 'int32',
        'sbytes': 'int64',
        'dbytes': 'int64',
        'rate': 'float64',
        'sttl': 'int32',
        'dttl': 'int32',
        'sload': 'float64',
        'dload': 'float64',
        'sloss': 'int32',
        'dloss': 'int32',
        'sinpkt': 'float64',
        'dinpkt': 'float64',
        'sjit': 'float64',
        'djit': 'float64',
        'swin': 'int32',
        'stcpb': 'int32',
        'dtcpb': 'int32',
        'dwin': 'int32',
        'tcprtt': 'float64',
        'synack': 'float64',
        'ackdat': 'float64',
        'smean': 'float64',
        'dmean': 'float64',
        'trans_depth': 'int64',
        'response_body_len': 'int64',
        'ct_srv_src': 'int64',
        'ct_state_ttl': 'int64',
        'ct_dst_ltm': 'int64',
        'ct_src_ ltm': 'int64',
        'ct_src_dport_ltm': 'int64',
        'ct_dst_sport_ltm': 'int64',
        'ct_dst_src_ltm': 'int64',
        'attack_cat': 'object',
        'label': 'object'
    }
