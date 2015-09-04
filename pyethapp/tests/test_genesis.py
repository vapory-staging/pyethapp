from ethereum import blocks
from ethereum.db import DB
from ethereum.config import Env
from pyethapp.utils import merge_dict
from pyethapp.utils import update_config_from_genesis_json
import pyethapp.config as konfig
from pyethapp.profiles import PROFILES


def test_genesis():
    for profile in ['frontier']:  # fixme olympics

        config = dict(eth=dict())

        # Set config values based on profile selection
        merge_dict(config, PROFILES[profile])

        # Load genesis config
        update_config_from_genesis_json(config, config['eth']['genesis'])

        konfig.update_config_with_defaults(config, {'eth': {'block': blocks.default_config}})

        print config['eth'].keys()
        bc = config['eth']['block']
        print bc.keys()
        env = Env(DB(), bc)

        genesis = blocks.genesis(env)
        print 'genesis.hash', genesis.hash.encode('hex')
        print 'expected', config['eth']['genesis_hash']
        assert genesis.hash == config['eth']['genesis_hash'].decode('hex')


if __name__ == '__main__':
    test_genesis()
