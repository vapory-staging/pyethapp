import os
import shutil
import tempfile
from uuid import uuid4
from devp2p.app import BaseApp
import pytest
from pyethapp.accounts import Account, AccountsService


@pytest.fixture()
def app(request):
    app = BaseApp(config=dict(accounts=dict(keystore_dir=tempfile.mkdtemp())))
    AccountsService.register_with_app(app)

    def fin():
        # cleanup temporary keystore directory
        assert app.config['accounts']['keystore_dir'].startswith(tempfile.gettempdir())
        shutil.rmtree(app.config['accounts']['keystore_dir'])
    request.addfinalizer(fin)

    return app


@pytest.fixture(scope='module')
def privkey():
    return 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'


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


def test_empty(app):
    s = app.services.accounts
    assert len(s) == 0
    assert len(s.accounts_with_address()) == 0
    assert len(s.unlocked_accounts()) == 0
    assert s.accounts == []


def test_add_account(app, account):
    s = app.services.accounts
    assert len(s) == 0
    s.add_account(account)
    assert len(s) == 1
    assert s.accounts == [account]
    assert s[account.address] == account
    assert s.unlocked_accounts() == [account]
    assert s.accounts_with_address() == [account]
    assert s.get_by_id(account.uuid) == account


def test_add_locked_account(app, account, password):
    s = app.services.accounts
    account.lock()
    assert account.address is not None
    s.add_account(account)
    assert s.accounts == [account]
    assert s[account.address] == account
    assert len(s.unlocked_accounts()) == 0
    assert s.accounts_with_address() == [account]
    assert s.get_by_id(account.uuid) == account
    account.unlock(password)
    assert s.unlocked_accounts() == [account]


def test_add_account_without_address(app, account, password):
    s = app.services.accounts
    account.lock()
    address = account.address
    account._address = None
    s.add_account(account)
    assert s.accounts == [account]
    assert len(s.unlocked_accounts()) == 0
    assert len(s.accounts_with_address()) == 0
    with pytest.raises(KeyError):
        s[address]
    assert s.get_by_id(account.uuid) == account
    account._address = address  # restore address for following tests
    account.unlock(password)


def test_add_account_twice(app, account):
    s = app.services.accounts
    s.add_account(account)
    with pytest.raises(ValueError):
        s.add_account(account)
    assert len(s.accounts) == 1
    uuid = account.uuid
    account.uuid = None
    s.add_account(account)
    assert len(s) == 2
    assert s.accounts == [account, account]
    assert s[account.address] == account
    assert s.unlocked_accounts() == [account, account]
    assert s.accounts_with_address() == [account, account]
    account.uuid = uuid


def test_lock_after_adding(app, account, password):
    s = app.services.accounts
    s.add_account(account)
    assert s.unlocked_accounts() == [account]
    account.lock()
    assert len(s.unlocked_accounts()) == 0
    account.unlock(password)
    assert s.unlocked_accounts() == [account]


def test_find(app, account):
    s = app.services.accounts
    s.add_account(account)
    assert len(s) == 1
    assert s.find('1') == account
    assert s.find(account.address.encode('hex')) == account
    assert s.find(account.address.encode('hex').upper()) == account
    assert s.find('0x' + account.address.encode('hex')) == account
    assert s.find('0x' + account.address.encode('hex').upper()) == account
    assert s.find(account.uuid) == account
    assert s.find(account.uuid.upper()) == account
    with pytest.raises(ValueError):
        s.find('')
    with pytest.raises(ValueError):
        s.find('aabbcc')
    with pytest.raises(ValueError):
        s.find('xx' * 20)
    with pytest.raises(ValueError):
        s.find('0x' + 'xx' * 20)
    with pytest.raises(KeyError):
        s.find('ff' * 20)
    with pytest.raises(KeyError):
        s.find('0x' + 'ff' * 20)
    with pytest.raises(KeyError):
        s.find(str(uuid4()))


def test_store(app, account):
    s = app.services.accounts
    s.add_account(account, path='account1', include_id=True, include_address=True)
    path = os.path.join(app.config['accounts']['keystore_dir'], 'account1')
    assert os.path.exists(path)
    account_reloaded = Account.load(path)
    assert account_reloaded.uuid is not None
    assert account_reloaded.address is not None
    assert account_reloaded.uuid == account.uuid
    assert account_reloaded.address == account.address
    assert account_reloaded.privkey is None
    assert account.privkey is not None


def test_store_overwrite(app, account):
    s = app.services.accounts
    uuid = account.uuid
    account.uuid = None
    s.add_account(account, path='account1')
    with pytest.raises(IOError):
        s.add_account(account, path='account1')
    s.add_account(account, path='account2')
    account.uuid = uuid


def test_store_dir(app, account):
    s = app.services.accounts
    uuid = account.uuid
    account.uuid = None
    s.add_account(account, path='some/sub/dir/account1')
    s.add_account(account, path='some/sub/dir/account2')
    s.add_account(account, path='account1')
    with pytest.raises(IOError):
        s.add_account(account, path='some/sub/dir/account1')
    account.uuid = uuid


def test_store_private(app, account, password):
    s = app.services.accounts
    s.add_account(account, path='account1', include_id=False, include_address=False)
    path = os.path.join(app.config['accounts']['keystore_dir'], 'account1')
    account_reloaded = Account.load(path)
    assert account_reloaded.address is None
    assert account_reloaded.uuid is None
    account_reloaded.unlock(password)
    assert account_reloaded.address == account.address
    assert account_reloaded.uuid is None


def test_store_absolute(app, account):
    s = app.services.accounts
    tmpdir = tempfile.mkdtemp()
    path = os.path.join(tmpdir, 'account1')
    assert os.path.isabs(path)
    s.add_account(account, path=path)
    assert os.path.exists(path)
    account_reloaded = Account.load(path)
    assert account_reloaded.address == account.address
    shutil.rmtree(tmpdir)


def test_restart_service(app, account, password):
    s = app.services.accounts
    s.add_account(account, path='account1')
    app.services.pop('accounts')
    AccountsService.register_with_app(app)
    s = app.services.accounts
    assert len(s) == 1
    reloaded_account = s.accounts[0]
    assert reloaded_account.address == account.address
    assert reloaded_account.uuid == account.uuid
    assert reloaded_account.privkey is None
    assert reloaded_account.pubkey is None
    reloaded_account.unlock(password)
    assert reloaded_account.privkey == account.privkey
    assert reloaded_account.pubkey == account.pubkey
