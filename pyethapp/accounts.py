import json
import os
import random
from uuid import UUID
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

    :ivar keystore: the key store as a dictionary (as decoded from json)
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

        Note that this creates the account in memory and does not store it on disk.

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
        """Load an account from a keystore file.

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

        The result inherits the entries `'crypto'` and `'version`' from `account.keystore`, and
        adds `'address'` and `'id'` in accordance with the parameters `'include_address'` and
        `'include_id`'.

        If address or id are not known, they are not added, even if requested.

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
        """Unlock the account with a password.

        If the account is already unlocked, nothing happens, even if the password is wrong.

        :raises: :exc:`ValueError` (originating in ethereum.keys) if the password is wrong (and the
                 account is locked)
        """
        if self.locked:
            self._privkey = keys.decode_keystore_json(self.keystore, password)
            self.locked = False

    def lock(self):
        """Relock an unlocked account.

        This method sets `account.privkey` to `None` (unlike `account.address` which is preserved).
        After calling this method, both `account.privkey` and `account.pubkey` are `None.
        `account.address` stays unchanged, even if it has been derived from the private key.
        """
        self._privkey = None
        self.locked = True

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
            pass
        elif 'address' in self.keystore:
            self._address = self.keystore['address'].decode('hex')
        elif not self.locked:
            self._address = keys.privtoaddr(self.privkey)
        else:
            return None
        return self._address

    @property
    def uuid(self):
        """An optional unique identifier, formatted according to UUID version 4, or `None` if the
        account does not have an id
        """
        try:
            return self.keystore['id']
        except KeyError:
            return None

    @uuid.setter
    def uuid(self, value):
        """Set the UUID. Set it to `None` in order to remove it."""
        if value is not None:
            self.keystore['id'] = value
        elif 'id' in self.keystore:
            self.keystore.pop('id')

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

    def find(self, identifier):
        """Find an account by either its address, its id or its index as string.

        Example identifiers:

        - '9c0e0240776cfbe6fa1eb37e57721e1a88a563d1' (address)
        - '0x9c0e0240776cfbe6fa1eb37e57721e1a88a563d1' (address with 0x prefix)
        - '01dd527b-f4a5-4b3c-9abb-6a8e7cd6722f' (UUID)
        - '3' (index)

        :param identifier: the accounts hex encoded address (with optional 0x prefix), its UUID or
                           its index (as string, >= 1) in `account_service.accounts`
        :raises: :exc:`ValueError` if the identifier could not be interpreted
        :raises: :exc:`KeyError` if the identified account is not known to the account_service
        """
        try:
            uuid = UUID(identifier)
        except ValueError:
            pass
        else:
            return self.get_by_id(str(uuid))

        try:
            index = int(identifier, 10)
        except ValueError:
            pass
        else:
            if index <= 0:
                raise ValueError('Index must be 1 or greater')
            try:
                return self.accounts[index - 1]
            except IndexError as e:
                raise KeyError(e.message)

        if identifier[:2] == '0x':
            identifier = identifier[2:]
        try:
            address = identifier.decode('hex')
        except ValueError:
            success = False
        else:
            if len(address) != 20:
                success = False
            else:
                return self[address]

        assert not success
        raise ValueError('Could not interpret account identifier')

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
