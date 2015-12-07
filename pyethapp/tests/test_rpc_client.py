from pyethapp.rpc_client import JSONRPCClient

def test_find_block():
    JSONRPCClient.call = lambda self, cmd, num, flag: num
    client = JSONRPCClient()
    client.find_block(lambda x: x == '0x5')
