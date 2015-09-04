from os import path

DEFAULT_PROFILE = 'frontier'

PROFILES = {
    'frontier': {
        'eth': {
            'network_id': 1,
            'genesis': path.abspath(path.join(path.dirname(__file__), '..',
                                              'data', 'genesis_frontier.json')),
            'genesis_hash': 'd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3'
        }
    },
    'olympic': {
        'eth': {
            'network_id': 0,
            'genesis': path.abspath(path.join(path.dirname(__file__), '..',
                                              'data', 'genesis_olympic.json')),
            'genesis_hash': 'fd4af92a79c7fc2fd8bf0d342f2e832e1d4f485c85b9152d2039e03bc604fdca'
        }
    },
}
