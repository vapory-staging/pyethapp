import json
from uuid import uuid4
from ethereum.keys import privtoaddr
from ethereum.transactions import Transaction
from pyethapp.accounts import Account
import pytest


@pytest.fixture(scope='module')
def privkey():
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'.decode('hex')


@pytest.fixture(scope='module')
def password():
    return 'secret'


@pytest.fixture(scope='module')
def uuid():
    return str(uuid4())


# keystore generation takes a while, so make this module scoped
@pytest.fixture(scope='module')
def account(privkey, password, uuid):
    return Account.new(password, privkey, uuid)


@pytest.fixture(scope='module')
def keystore(account):
    # `account.keystore` might not contain address and id
    return json.loads(account.dump())


def test_account_creation(account, password, privkey, uuid):
    assert not account.locked
    assert account.privkey == privkey
    assert account.address == privtoaddr(privkey)
    assert account.uuid == uuid


def test_locked(keystore, uuid):
    account = Account(keystore)
    assert account.locked
    assert account.address.encode('hex') == keystore['address']
    assert account.privkey is None
    assert account.pubkey is None
    assert account.uuid == uuid
    keystore2 = keystore.copy()
    keystore2.pop('address')
    account = Account(keystore2)
    assert account.locked
    assert account.address is None
    assert account.privkey is None
    assert account.pubkey is None
    assert account.uuid == uuid


def test_unlock(keystore, password, privkey, uuid):
    account = Account(keystore)
    assert account.locked
    account.unlock(password)
    assert not account.locked
    assert account.privkey == privkey
    assert account.address == privtoaddr(privkey)


def test_unlock_wrong(keystore, password, privkey, uuid):
    account = Account(keystore)
    assert account.locked
    with pytest.raises(ValueError):
        account.unlock(password + '1234')
    assert account.locked
    with pytest.raises(ValueError):
        account.unlock('4321' + password)
    assert account.locked
    with pytest.raises(ValueError):
        account.unlock(password[:len(password) / 2])
    assert account.locked
    account.unlock(password)
    assert not account.locked
    account.unlock(password + 'asdf')
    assert not account.locked
    account.unlock(password + '1234')
    assert not account.locked


def test_lock(account, password, privkey):
    assert not account.locked
    assert account.address == privtoaddr(privkey)
    assert account.privkey == privkey
    assert account.pubkey is not None
    account.unlock(password + 'fdsa')
    account.lock()
    assert account.locked
    assert account.address == privtoaddr(privkey)
    assert account.privkey is None
    assert account.pubkey is None
    with pytest.raises(ValueError):
        account.unlock(password + 'fdsa')
    account.unlock(password)


def test_dump(account):
    keystore = json.loads(account.dump(include_address=True, include_id=True))
    required_keys = set(['crypto', 'version'])
    assert set(keystore.keys()) == required_keys | set(['address', 'id'])
    assert keystore['address'] == account.address.encode('hex')
    assert keystore['id'] == account.uuid

    keystore = json.loads(account.dump(include_address=False, include_id=True))
    assert set(keystore.keys()) == required_keys | set(['id'])
    assert keystore['id'] == account.uuid

    keystore = json.loads(account.dump(include_address=True, include_id=False))
    assert set(keystore.keys()) == required_keys | set(['address'])
    assert keystore['address'] == account.address.encode('hex')

    keystore = json.loads(account.dump(include_address=False, include_id=False))
    assert set(keystore.keys()) == required_keys


def test_uuid_setting(account):
    uuid = account.uuid
    account.uuid = 'asdf'
    assert account.uuid == 'asdf'
    account.uuid = None
    assert account.uuid is None
    assert 'id' not in account.keystore
    account.uuid = uuid
    assert account.uuid == uuid
    assert account.keystore['id'] == uuid


def test_sign(account, password):
    tx = Transaction(1, 0, 0, account.address, 0, '')
    account.sign_tx(tx)
    assert tx.sender == account.address
    account.lock()
    with pytest.raises(ValueError):
        account.sign_tx(tx)
    account.unlock(password)
