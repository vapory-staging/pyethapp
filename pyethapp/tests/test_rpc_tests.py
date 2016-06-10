import os
import pytest
from click.testing import CliRunner

from pyethapp import app

@pytest.mark.skipif(os.getenv('TRAVIS') != None, reason="don't start external test on travis")
def test_externally(tmpdir):
    # The results of the external rpc-tests are not evaluated as:
    #  1) the Whisper protocol is not implemented and its tests fail;
    #  2) the eth_accounts method should be skipped;
    #  3) the eth_getFilterLogs fails due to the invalid test data;
    os.system('''
        git clone https://github.com/ethereum/rpc-tests;
        cd rpc-tests;
        git submodule update --init --recursive;
        npm install;
    ''')
    runner = CliRunner()

    result = runner.invoke(app.app, [
        '-d', str(tmpdir),
        '-l:info,eth.chainservice:debug,jsonrpc:debug',
        '-c jsonrpc.listen_port=8081',
        '-c p2p.max_peers=0',
        '-c p2p.min_peers=0',
        'blocktest'
        'lib/tests/BlockchainTests/bcRPC_API_Test.json',
        'RPC_API_Test'
    ])

