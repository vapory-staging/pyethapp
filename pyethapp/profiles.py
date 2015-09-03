from os import path

DEFAULT_PROFILE = 'frontier'

PROFILES = {
    'frontier': {
        'eth': {
            'network_id': 1,
            'genesis': path.join(path.dirname(__file__), 'data', 'genesis_frontier.json'),
        }
    },
    'olympic': {
        'eth': {
            'network_id': 0,
            'genesis': path.join(path.dirname(__file__), 'data', 'genesis_olympic.json'),
        }
    },
}
