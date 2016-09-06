import sys
import time
import json

from ethereum import utils
from ethereum.state_transition import apply_const_message
from ethereum.casper_utils import RandaoManager, generate_validation_code, make_casper_genesis, casper_config, call_casper

def generate_genesis(path, num_participants=1):
    privkeys = [utils.sha3(str(i)) for i in range(num_participants)]
    addrs = [utils.privtoaddr(k) for k in privkeys]
    deposit_sizes = [i * 500 + 500 for i in range(num_participants)]
    randaos = [RandaoManager(utils.sha3(k)) for k in privkeys]

    validators = [(generate_validation_code(a), ds * 10**18, r.get(9999), a) for a, ds, r in zip(addrs, deposit_sizes, randaos)]
    s = make_casper_genesis(validators=validators,
                            alloc={a: {'balance': 10**18} for a in addrs},
                            timestamp=int(time.time()),
                            epoch_length=100)
    genesis_hash = apply_const_message(s,
                                       sender=casper_config['METROPOLIS_ENTRY_POINT'],
                                       to=casper_config['METROPOLIS_BLOCKHASH_STORE'],
                                       data=utils.encode_int32(0))
    genesis_number = call_casper(s, 'getBlockNumber')
    print 'genesis block hash: %s' % utils.encode_hex(genesis_hash)
    print 'genesis block number: %d' % genesis_number

    snapshot = s.to_snapshot()
    header = s.prev_headers[0]
    genesis = {
        "nonce": "0x" + utils.encode_hex(header.nonce),
        "difficulty": utils.int_to_hex(header.difficulty),
        "mixhash": "0x" + utils.encode_hex(header.mixhash),
        "coinbase": "0x" + utils.encode_hex(header.coinbase),
        "timestamp": utils.int_to_hex(header.timestamp),
        "parentHash": "0x" + utils.encode_hex(header.prevhash),
        "extraData": "0x" + utils.encode_hex(header.extra_data),
        "gasLimit": utils.int_to_hex(header.gas_limit),
        "alloc": snapshot["alloc"]
    }
    with open(path, 'w') as f:
        json.dump(genesis, f)
    print 'casper genesis generated'


if __name__ == "__main__":
    if sys.argv[1] == "genesis":
        generate_genesis(sys.argv[2])
    else:
        print "unknown command: %s" % sys.argv[1]
        sys.exit(1)
