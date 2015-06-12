from ethereum.keys import privtoaddr
from pyethapp.accounts import Account


def test_account_creation():
    privkey = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    account = Account.new('secret', privkey)
    assert account.address
    assert account.privkey == privkey
    assert account.address == privtoaddr(privkey)
