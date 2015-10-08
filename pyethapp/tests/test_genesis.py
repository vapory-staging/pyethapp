from pprint import pprint
import pytest
from ethereum import blocks
from ethereum.db import DB
from ethereum.config import Env
from pyethapp.utils import merge_dict
from pyethapp.utils import update_config_from_genesis_json
import pyethapp.config as konfig
from pyethapp.profiles import PROFILES


@pytest.mark.parametrize('profile', PROFILES.keys())
def test_profile(profile):
    config = dict(eth=dict())

    konfig.update_config_with_defaults(config, {'eth': {'block': blocks.default_config}})

    # Set config values based on profile selection
    merge_dict(config, PROFILES[profile])

    # Load genesis config
    update_config_from_genesis_json(config, config['eth']['genesis'])

    bc = config['eth']['block']
    pprint(bc)
    env = Env(DB(), bc)

    genesis = blocks.genesis(env)
    assert genesis.hash.encode('hex') == config['eth']['genesis_hash']
