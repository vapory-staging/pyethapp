import rlp
from ethereum.blocks import Account
from ethereum.utils import is_numeric, is_string, encode_hex
from ethereum.securetrie import SecureTrie
from ethereum.trie import Trie, BLANK_NODE


def create_snapshot(block):
    env = block.env
    db = block.db
    snapshot = dict()

    alloc = dict()
    for addr, account_rlp in block.state.to_dict().items():
        alloc[encode_hex(addr)] = create_account_snapshot(env, db, account_rlp)
    snapshot['alloc'] = alloc

    return snapshot


def load_snapshot(snapshot):
    pass


def create_account_snapshot(env, db, rlpdata):
    account = get_account(env, db, rlpdata)
    storage_trie = SecureTrie(Trie(db, account.storage))
    storage = dict()
    for k, v in storage_trie.to_dict().items():
        storage[encode_hex(k.lstrip('\x00') or '\x00')] = encode_hex(rlp.decode(v))
    return {
        'nonce': snapshot_form(account.nonce),
        'balance': snapshot_form(account.balance),
        'code_hash': snapshot_form(account.code_hash),
        'storage': storage
    }


def get_account(env, db, rlpdata):
    if rlpdata != BLANK_NODE:
        return rlp.decode(rlpdata, Account, db=db)
    else:
        return Account.blank_account(db, env.config['ACCOUNT_INITIAL_NONCE'])


def snapshot_form(val):
    if is_numeric(val):
        return str(val)
    elif is_string(val):
        return b'0x' + encode_hex(val)
