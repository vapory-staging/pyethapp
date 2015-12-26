"""
Support for simple yaml persisted config dicts.

Usual building of the configuration
 - with datadir (default or from option)
    - create dir if not available
        - create minimal config if not available
    - load config
 - App is initialized with an (possibly empty) config
    which is recursively updated (w/o overriding values) with its own default config
 - Services are initialized with app and
    recursively update (w/o overriding values) the config with their default config

todo:
    datadir


"""
import os
import copy
import click
from devp2p.utils import update_config_with_defaults # updates only missing entries
import errno
import yaml
import ethereum.slogging as slogging
from devp2p.service import BaseService
from devp2p.app import BaseApp
from accounts import mk_random_privkey
from ethereum.keys import decode_hex
from ethereum.utils import parse_int_or_hex, remove_0x_head


CONFIG_FILE_NAME = 'config.yaml'

log = slogging.get_logger('config')

default_data_dir = click.get_app_dir('pyethapp')


def get_config_path(data_dir=default_data_dir):
    return os.path.join(data_dir, CONFIG_FILE_NAME)

default_config_path = get_config_path(default_data_dir)


def setup_data_dir(data_dir=None):
    config_file_path = get_config_path(data_dir)
    if data_dir and not os.path.exists(config_file_path):
        try:
            os.makedirs(data_dir)
        except OSError as ex:
            # Ignore "File exists" errors
            if ex.errno != errno.EEXIST:
                raise
        setup_required_config(data_dir)


required_config = dict(node=dict(privkey_hex=''))


def check_config(config, required_config=required_config):
    "check if values are set"
    for k, v in required_config.items():
        if not config.get(k):
            return False
        if isinstance(v, dict):
            if not check_config(config[k], v):
                return False
    return True


def validate_alt_config_file(ctx, param, value):
    """Used as a click.callback
    Check if config file @value can be used as a pyethapp config"
    """
    if value:
        try:
            yaml_ = load_config(value)
        except IOError, e:
            raise click.BadParameter(str(e))
        else:
            if not isinstance(yaml_, dict):
                raise click.BadParameter('content of config should be an yaml dictionary')
            assert not yaml_.get('eth', {}).get('privkey_hex'), 'eth.privkey_hex found'
    return value


def setup_required_config(data_dir=default_data_dir):
    "writes minimal necessary config to data_dir"
    log.info('setup default config', path=data_dir)
    config_path = get_config_path(data_dir)
    assert not os.path.exists(config_path)
    if not os.path.exists(data_dir):
        setup_data_dir(data_dir)
    config = dict(node=dict(privkey_hex=mk_random_privkey().encode('hex')))
    write_config(config, config_path)


def get_default_config(services):
    "collect default_config from services"
    config = dict()
    assert isinstance(services, list)
    for s in services:
        assert isinstance(s, (BaseService, BaseApp)) or issubclass(s, (BaseService, BaseApp))
        update_config_with_defaults(config, s.default_config)
    return config


def load_config(path=default_config_path):
    """Load config from string or file like object `path`."""
    log.info('loading config', path=path)
    if os.path.exists(path):
        if os.path.isdir(path):
            path = get_config_path(path)
        return yaml.load(open(path))
    return dict()


def write_config(config, path=default_config_path):
    """Load config from string or file like object `f`, discarding the one
    already in place.
    """
    assert path
    log.info('writing config', path=path)
    with open(path, 'wb') as f:
        yaml.dump(config, f)


def set_config_param(config, s, strict=True):
    """Set a specific config parameter.

    :param s: a string of the form ``a.b.c=d`` which will set the value of
              ``config['a']['b']['b']`` to ``yaml.load(d)``
    :param strict: if `True` will only override existing values.
    :raises: :exc:`ValueError` if `s` is malformed or the value to set is not
             valid YAML
    """
    # fixme add += support
    try:
        param, value = s.split('=', 1)
        keys = param.split('.')
    except ValueError:
        raise ValueError('Invalid config parameter')
    d = config
    for key in keys[:-1]:
        if strict and key not in d:
            raise KeyError('Unknown config option %s' % param)
        d = d.setdefault(key, {})
    try:
        if strict and keys[-1] not in d:
            raise KeyError('Unknown config option %s' % param)
        d[keys[-1]] = yaml.load(value)
    except yaml.parser.ParserError:
        raise ValueError('Invalid config value')
    return config


def dump_config(config):
    """mask privkey_hex entries in config and print as yaml
    """
    konfig = copy.deepcopy(config)
    mask = lambda key: "{}{}{}".format(key[:2], "*" * (len(key) - 4), key[-2:])
    if len(konfig.get('accounts', {}).get('privkeys_hex', [])):
        konfig['accounts']['privkeys_hex'] = [mask(key) for key in konfig['accounts']['privkeys_hex']]
    if len(konfig.get('node', {}).get('privkey_hex')):
        konfig['node']['privkey_hex'] = mask(konfig['node']['privkey_hex'])
    print yaml.dump(konfig)


def update_config_from_genesis_json(config, genesis_json_filename_or_dict):
    if isinstance(genesis_json_filename_or_dict, dict):
        genesis_dict = genesis_json_filename_or_dict
    else:
        with open(genesis_json_filename_or_dict, "r") as genesis_json_file:
            genesis_dict = yaml.load(genesis_json_file)

    config.setdefault('eth', {}).setdefault('block', {})
    cfg = config['eth']['block']

    # map external to internal keys and decoders
    def _dec(x):
        return decode_hex(remove_0x_head(x))

    m = [
        ('GENESIS_INITIAL_ALLOC', 'alloc', lambda x: x),
        ('GENESIS_DIFFICULTY',  'difficulty', parse_int_or_hex),
        ('GENESIS_TIMESTAMP',  'timestamp', parse_int_or_hex),
        ('GENESIS_EXTRA_DATA',  'extraData', _dec),
        ('GENESIS_GAS_LIMIT',  'gasLimit', parse_int_or_hex),
        ('GENESIS_MIXHASH', 'mixhash', _dec),
        ('GENESIS_PREVHASH',  'parentHash', _dec),
        ('GENESIS_COINBASE',  'coinbase', _dec),
        ('GENESIS_NONCE',  'nonce', _dec)
    ]

    m = dict((in_key, (target_key, translator_func)) for target_key, in_key, translator_func in m)

    for k, v in genesis_dict.items():
        target_key, translator_func = m[k]
        cfg[target_key] = translator_func(v)

    return config
