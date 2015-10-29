from os import path
from ethereum.utils import denoms


DEFAULT_PROFILE = 'frontier'

genesisdata_dir = path.abspath(path.join(path.dirname(__file__), 'genesisdata'))

PROFILES = {
    'frontier': {
        'eth': {
            'network_id': 1,
            'genesis': path.join(genesisdata_dir, 'genesis_frontier.json'),
            'genesis_hash': 'd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'
        }
    },
    'morden': {
        'eth': {
            'network_id': 2,
            'genesis': path.join(genesisdata_dir, 'genesis_morden.json'),
            'genesis_hash': '0cd786a2425d16f152c658316c423e6ce1181e15c3295826d7c9904cba9ce303',
            'block': {
                'ACCOUNT_INITIAL_NONCE': 2 ** 20
            },
            'discovery': {
                'bootstrap_nodes': [
                    (
                        'enode://e58d5e26b3b630496ec640f2530f3e7fa8a8c7dfe79d9e9c4aac80e3730132b8'
                        '69c852d3125204ab35bb1b1951f6f2d40996c1034fd8c5a69b383ee337f02ddc'
                        '@92.51.165.126:30303'
                    )
                ]
            }
        },
    }
}
