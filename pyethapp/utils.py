from collections import Mapping
import json
import yaml
import os
import ethereum
from ethereum.blocks import Block, genesis
from ethereum.keys import decode_hex
from ethereum.utils import parse_int_or_hex, remove_0x_head
from devp2p.service import BaseService
import re
import rlp
import sys
from ethereum import slogging
import types

slogging.set_level('db', 'debug')
log = slogging.get_logger('db')


def load_contrib_services(config):  # FIXME
    # load contrib services
    config_directory = config['data_dir']
    print 'dir', config_directory
    contrib_directory = os.path.join(config_directory, 'contrib')  # change to pyethapp/contrib
    contrib_modules = []
    print 'dir', contrib_directory
    if not os.path.exists(contrib_directory):
        log.info('No contrib directory found, so not loading any user services')
        sys.exit()
        return []
    x = os.getcwd()
    os.chdir(config_directory)
    for filename in os.listdir(contrib_directory):
        if filename.endswith('.py'):
            print filename
            try:
                __import__(filename[:-3])
                library_conflict = True
            except:
                library_conflict = False
            if library_conflict:
                raise Exception("Library conflict: please rename "+filename+" in contribs")
            sys.path.append(contrib_directory)
            contrib_modules.append(__import__(filename[:-3]))
            sys.path.pop()
    print 'modules', contrib_modules
    contrib_services = []
    for module in contrib_modules:
        print 'm', module, dir(module)
        on_start, on_block = None, None
        for variable in dir(module):
            cls = getattr(module, variable)
            if isinstance(cls, (type, types.ClassType)):
                print 'class', issubclass(cls, BaseService)
                if issubclass(cls, BaseService) and cls != BaseService:
                    contrib_services.append(cls)
            if variable == 'on_block':
                on_block = getattr(module, variable)
            if variable  == 'on_start':
                on_start = getattr(module, variable)
        if on_start or on_block:
            contrib_services.append(OnBlockClassFactory(on_start, on_block))
    log.info('Loaded contrib services', services=contrib_services)
    print contrib_services
    return contrib_services

services_registered = 0


def OnBlockClassFactory(on_start, on_block):
    global services_registered
    x = [services_registered]
    services_registered += 1
    class MyService(BaseService):
    
        name = 'factory generated service %d' % x[0]
    
        def start(self):
            super(MyService, self).start()
            self.app.services.chain.on_new_head_cbs.append(self.cb)
            if on_start:
                on_start(self.app)
    
        def cb(self, blk):
            if on_block:
                on_block(blk)
    return MyService


def load_block_tests(data, db):
    """Load blocks from json file.

    :param data: the data from the json file as dictionary
    :param db: the db in which the blocks will be stored
    :raises: :exc:`ValueError` if the file contains invalid blocks
    :raises: :exc:`KeyError` if the file is missing required data fields
    :returns: a list of blocks in an ephem db
    """
    scanners = ethereum.utils.scanners
    initial_alloc = {}
    for address, acct_state in data['pre'].items():
        address = ethereum.utils.decode_hex(address)
        balance = scanners['int256b'](acct_state['balance'][2:])
        nonce = scanners['int256b'](acct_state['nonce'][2:])
        initial_alloc[address] = {
            'balance': balance,
            'code': acct_state['code'],
            'nonce': nonce,
            'storage': acct_state['storage']
        }
    genesis(db, start_alloc=initial_alloc)  # builds the state trie
    genesis_block = rlp.decode(ethereum.utils.decode_hex(data['genesisRLP'][2:]), Block, db=db)
    blocks = {genesis_block.hash: genesis_block}
    for blk in data['blocks']:
        rlpdata = ethereum.utils.decode_hex(blk['rlp'][2:])
        assert ethereum.utils.decode_hex(blk['blockHeader']['parentHash']) in blocks
        parent = blocks[ethereum.utils.decode_hex(blk['blockHeader']['parentHash'])]
        block = rlp.decode(rlpdata, Block, db=db, parent=parent)
        blocks[block.hash] = block
    return sorted(blocks.values(), key=lambda b: b.number)


def update_config_from_genesis_json(config, genesis_json_filename):
    with open(genesis_json_filename, "r") as genesis_json_file:
        genesis_dict = yaml.load(genesis_json_file)

    config.setdefault('eth', {}).setdefault('block', {})
    cfg = config['eth']['block']
    cfg['GENESIS_INITIAL_ALLOC'] = genesis_dict['alloc']
    cfg['GENESIS_DIFFICULTY'] = parse_int_or_hex(genesis_dict['difficulty'])
    cfg['GENESIS_TIMESTAMP'] = parse_int_or_hex(genesis_dict['timestamp'])
    cfg['GENESIS_EXTRA_DATA'] = decode_hex(remove_0x_head(genesis_dict['extraData']))
    cfg['GENESIS_GAS_LIMIT'] = parse_int_or_hex(genesis_dict['gasLimit'])
    cfg['GENESIS_MIXHASH'] = decode_hex(remove_0x_head(genesis_dict['mixhash']))
    cfg['GENESIS_PREVHASH'] = decode_hex(remove_0x_head(genesis_dict['parentHash']))
    cfg['GENESIS_COINBASE'] = decode_hex(remove_0x_head(genesis_dict['coinbase']))
    cfg['GENESIS_NONCE'] = decode_hex(remove_0x_head(genesis_dict['nonce']))

    return config


def merge_dict(dest, source):
    stack = [(dest, source)]
    while stack:
        curr_dest, curr_source = stack.pop()
        for key in curr_source:
            if key not in curr_dest:
                curr_dest[key] = curr_source[key]
            else:
                if isinstance(curr_source[key], Mapping):
                    if isinstance(curr_dest[key], Mapping):
                        stack.append((curr_dest[key], curr_source[key]))
                    else:
                        raise ValueError('Incompatible types during merge: {} and {}'.format(
                            type(curr_source[key]),
                            type(curr_dest[key])
                        ))
                else:
                    curr_dest[key] = curr_source[key]
    return dest
