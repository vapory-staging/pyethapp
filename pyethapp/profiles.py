from os import path
from ethereum.utils import denoms
DEFAULT_PROFILE = 'frontier'

PROFILES = {
    'frontier': {
        'eth': {
            'network_id': 1,
            'genesis': path.abspath(path.join(path.dirname(__file__),
                                              'data', 'genesis_frontier.json')),
            'genesis_hash': 'd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'
        }
    },
    'olympic': {
        'eth': {
            'network_id': 0,
            'genesis': path.abspath(path.join(path.dirname(__file__),
                                              'data', 'genesis_olympic.json')),
            'genesis_hash': 'fd4af92a79c7fc2fd8bf0d342f2e832e1d4f485c85b9152d2039e03bc604fdca'
        }
    },
}


olympic_params = dict(
    MIN_GAS_LIMIT=125000,
    GASLIMIT_EMA_FACTOR=1024,
    GASLIMIT_ADJMAX_FACTOR=1024,
    BLKLIM_FACTOR_NOM=3,
    BLKLIM_FACTOR_DEN=2,
    BLOCK_REWARD=1500 * denoms.finney,
    UNCLE_DEPTH_PENALTY_FACTOR=8,
    NEPHEW_REWARD=(1500 * denoms.finney) // 32,
    MAX_UNCLE_DEPTH=6,
    MAX_UNCLES=2,
    DIFF_ADJUSTMENT_CUTOFF=8,
    BLOCK_DIFF_FACTOR=2048,
    MIN_DIFF=131072,
    POW_EPOCH_LENGTH=30000)

PROFILES['olympic']['eth']['block'] = olympic_params
