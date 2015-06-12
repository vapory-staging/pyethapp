import json
import os
import random
from devp2p.service import BaseService
from ethereum import keys
from ethereum.slogging import get_logger
from ethereum.utils import privtopub  # this is different  than the one used in devp2p.crypto
from ethereum.utils import sha3
log = get_logger('accounts')


def mk_privkey(seed):
    return sha3(seed)


def mk_random_privkey():
    k = hex(random.getrandbits(256))[2:-1].zfill(64)
    assert len(k) == 64
    return k.decode('hex')


class Account(object):
    """Represents an account.

    :ivar keystore: the key store as a dictionary (decoded from json)
    :ivar locked: `True` if the account is locked and neither private nor public keys can be
                  accessed, otherwise `False`
    """

    def __init__(self, keystore, password=None):
        self.keystore = keystore
        try:
            self._address = self.keystore['address'].decode('hex')
        except KeyError:
            self._address = None
        self.locked = True
        if password is not None:
            self.unlock(password)

    @classmethod
    def new(cls, password, key=None, uuid=None):
        """Create a new account.

        Note that the account will not be stored on disk.

        :param password: the password used to encrypt the private key
        :param key: the private key, or `None` to generate a random one
        :param uuid: an optional id
        """
        if not key:
            key = mk_random_privkey()
        keystore = keys.make_keystore_json(key, password)
        keystore['id'] = uuid
        return Account(keystore, password)

    @classmethod
    def load(cls, f, password=None):
        """Load an account from a key file.

        :param f: either a path to the keyfile or the opened key file.
        :param password: the password to decrypt the key file or `None` to leave it encrypted
        """
        try:
            keystore = json.load(f)
        except AttributeError:
            with open(f) as opened:
                keystore = json.load(opened)
        return Account(keystore, password)

    def dump(self, include_address=True, include_id=True):
        """Dump the keystore for later disk storage.

        :param include_address: flag denoting if the address should be included or not
        :param include_id: flag denoting if the id should be included or not
        """
        d = {}
        d['crypto'] = self.keystore['crypto']
        d['version'] = self.keystore['version']
        if include_address and self.address is not None:
            d['address'] = self.address.encode('hex')
        if include_id and self.uuid is not None:
            d['id'] = self.uuid
        return json.dumps(d)

    def unlock(self, password):
        """Unlock the account with a password."""
        # TODO wrong password
        self._privkey = keys.decode_keystore_json(self.keystore, password)
        self.locked = False

    @property
    def privkey(self):
        """The account's private key or `None` if the account is locked"""
        if not self.locked:
            return self._privkey
        else:
            return None

    @property
    def pubkey(self):
        """The account's public key or `None` if the account is locked"""
        if not self.locked:
            return privtopub(self.privkey)
        else:
            return None

    @property
    def address(self):
        """The account's address or `None` if the address is not stored in the key file and cannot
        be reconstructed (because the account is locked)
        """
        if self._address:
            return self._address
        elif not self.locked:
            self._address = keys.privtoaddr(self.privkey)
            return self._address
        else:
            return None

    @property
    def uuid(self):
        """An optional unique identifier, formatted according to UUID version 4, or `None` if the
        account does not have an id
        """
        try:
            return self.keystore['id']
        except KeyError:
            return None

    def __repr__(self):
        if self.address is not None:
            address = self.address.encode('hex')
        else:
            address = '?'
        return '<Account(address={address}, id={id})>'.format(address=address, id=self.uuid)


class AccountsService(BaseService):
    """Service that manages accounts.

    At initialization, this service collects the accounts stored as key files in the keystore
    directory (config option `accounts.keystore_dir`) and below.

    To add more accounts, use :method:`add_account`.

    :ivar accounts: the :class:`Account`s managed by this service
    :ivar keystore_dir: absolute path to the keystore directory
    """

    name = 'accounts'
    default_config = dict(accounts=dict(keystore_dir='keystore'))

    def __init__(self, app):
        super(AccountsService, self).__init__(app)
        self.keystore_dir = app.config['accounts']['keystore_dir']
        if not os.path.isabs(self.keystore_dir):
            self.keystore_dir = os.path.join(app.config['data_dir'], self.keystore_dir)
        self.accounts = []
        if not os.path.exists(self.keystore_dir):
            log.warning('keystore directory does not exist', directory=self.keystore_dir)
        elif not os.path.isdir(self.keystore_dir):
            log.error('configured keystore directory is a file, not a directory',
                      directory=self.keystore_dir)
        else:
            # traverse file tree rooted at keystore_dir
            log.info('searching for key files', directory=self.keystore_dir)
            for dirpath, _, filenames in os.walk(self.keystore_dir):
                for filename in [os.path.join(dirpath, filename) for filename in filenames]:
                    try:
                        self.accounts.append(Account.load(filename))
                    except ValueError:
                        log.warning('invalid file skipped in keystore directory',
                                    path=filename)
        if not self.accounts:
            log.warn('no accounts found')
        else:
            log.info('found account(s)', coinbase=self.coinbase.encode('hex'),
                     accounts=self.accounts)

    def add_account(self, account, path=None, include_address=True, include_id=True):
        """Add an account.

        To save the account on disk as a key file, pass a path to the desired location. It can
        either be absolute or relative to the keystore directory. `include_address` and
        `include_id` determine if address and id should be removed for storage or not.
        """
        log.info('adding account', account=account)
        if path:
            if not os.path.isabs(path):
                path = os.path.join(self.keystore_dir, path)
            if os.path.exists(path):
                log.error('File does already exist', path=path)
                raise IOError('File does already exist')
            try:
                with open(path, 'w') as f:
                    f.write(account.dump(include_address, include_id))
            except IOError as e:
                log.error('Could not write to file', path=path, message=e.strerror, errno=e.errno)
                raise
        self.accounts.append(account)

    def accounts_with_address(self):
        """Return a list of accounts whose address is known."""
        return [account for account in self if account.address]

    def unlocked_accounts(self):
        """Return a list of all unlocked accounts."""
        return [account for account in self if not account.locked]

    def get_by_id(self, id):
        """Return the account with a given id.

        Note that accounts are not required to have an id.

        :raises: `KeyError` if no matching account can be found
        """
        accts = [acct for acct in self.accounts if acct.id == id]
        assert len(accts) <= 1
        if len(accts) == 0:
            raise KeyError('account with id {} unknown'.format(id))
        else:
            return accts[0]

    def get_by_address(self, address):
        """Get an account by its address.

        Note that even if an account with the given address exists, it might not be found if it is
        locked.

        :raises: `KeyError` if no matching account can be found
        """
        assert len(address) == 20
        for account in self.accounts:
            if account.address == address:
                return account
        raise KeyError('account not found by address', address=address.encode('hex'))

    def unlock_all(self, password):
        """Try to unlock each locked account with the given password.

        :returns: a list of all accounts that have successfully been unlocked
        """
        unlocked = []
        for account in self.accounts:
            if account.locked:
                try:
                    account.unlock(password)
                except ValueError:
                    pass
                else:
                    unlocked.append(account)
        return unlocked

    @property
    def coinbase(self):
        return self.accounts[0].address

    def sign_tx(self, sender, tx):
        # should be moved to Account where individual rules can be implemented
        assert sender in self
        a = self[sender]
        log.info('signing tx', tx=tx, account=a)
        tx.sign(a.privkey)

    def __contains__(self, address):
        assert len(address) == 20
        return address in [a.address for a in self.accounts]

    def __getitem__(self, address):
        assert len(address) == 20
        for a in self.accounts:
            if a.address == address:
                return a
        raise KeyError

    def __iter__(self):
        return iter(self.accounts)

    def __len__(self):
        return len(self.accounts)


"""
--import-key = key.json
--unlock <password dialog>
--password  passwordfile
--newkey    <password dialog>


"""
