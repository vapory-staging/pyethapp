import rlp
from ethereum.blocks import Account
from ethereum.utils import is_numeric, is_string, encode_hex
from ethereum.securetrie import SecureTrie
from ethereum.trie import Trie, BLANK_NODE


def create_snapshot(block, recent=1024):
    env = block.env
    snapshot = create_genesis_snapshot(env)
    snapshot['alloc'] = create_state_snapshot(env, block.state)
    snapshot['blocks'] = create_blocks_snapshot(block, recent)
    return snapshot


def load_snapshot(snapshot):
    pass


def create_genesis_snapshot(env):
    return {
        'parentHash': snapshot_form(env.config['GENESIS_PREVHASH']),
        'coinbase': snapshot_form(env.config['GENESIS_COINBASE']),
        'difficulty': snapshot_form(env.config['GENESIS_DIFFICULTY']),
        'gasLimit': snapshot_form(env.config['GENESIS_GAS_LIMIT']),
        'timestamp': snapshot_form(env.config['GENESIS_TIMESTAMP']),
        'extraData': snapshot_form(env.config['GENESIS_EXTRA_DATA']),
        'mixhash': snapshot_form(env.config['GENESIS_MIXHASH']),
        'nonce': snapshot_form(env.config['GENESIS_NONCE'])
    }


def create_state_snapshot(env, state_trie):
    alloc = dict()
    for addr, account_rlp in state_trie.to_dict().items():
        alloc[encode_hex(addr)] = create_account_snapshot(env, account_rlp)
    return alloc


def create_account_snapshot(env, rlpdata):
    account = get_account(env, rlpdata)
    storage_trie = SecureTrie(Trie(env.db, account.storage))
    storage = dict()
    for k, v in storage_trie.to_dict().items():
        storage[encode_hex(k.lstrip('\x00') or '\x00')] = encode_hex(rlp.decode(v))
    return {
        'nonce': snapshot_form(account.nonce),
        'balance': snapshot_form(account.balance),
        'code_hash': snapshot_form(account.code_hash),
        'storage': storage
    }


def create_blocks_snapshot(block, limit):
    recent_blocks = list()
    for i in range(limit):
        recent_blocks.append(snapshot_form(rlp.encode(block)))
        if block.has_parent():
            block = block.get_parent()
        else:
            break
    recent_blocks.reverse()
    return recent_blocks


def get_account(env, rlpdata):
    if rlpdata != BLANK_NODE:
        return rlp.decode(rlpdata, Account, db=env.db)
    else:
        return Account.blank_account(env.db, env.config['ACCOUNT_INITIAL_NONCE'])


def snapshot_form(val):
    if is_numeric(val):
        return str(val)
    elif is_string(val):
        return b'0x' + encode_hex(val)
