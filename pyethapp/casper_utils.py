from ethereum import utils
from ethereum.casper_utils import RandaoManager, casper_config, get_casper_ct, \
    get_casper_code, get_rlp_decoder_code, get_hash_without_ed_code, \
    get_finalizer_code, generate_validation_code, call_casper
from ethereum.state_transition import apply_transaction
from ethereum.transactions import Transaction

num_participants = 3

casper_genesis = {
    "privkeys": [utils.sha3(str(i)) for i in range(num_participants)],
    "randaos": [RandaoManager(utils.sha3(str(i))) for i in range(num_participants)],
    "deposit_sizes": [256, 256, 128]
}
casper_genesis["addresses"] = [utils.privtoaddr(k) for k in casper_genesis["privkeys"]]

casper_genesis["validators"] = [(generate_validation_code(a), ds * 10**18, r.get(9999))
                                for a, ds, r in zip(
                                    casper_genesis["addresses"],
                                    casper_genesis["deposit_sizes"],
                                    casper_genesis["randaos"]
                                )]

def build_casper_genesis(state, validators, timestamp=0, epoch_length=100):
    state.gas_limit = 10**8 * (len(validators) + 1)
    state.prev_headers[0].timestamp = timestamp
    state.prev_headers[0].difficulty = 1
    state.timestamp = timestamp
    state.block_difficulty = 1

    state.set_code(casper_config['CASPER_ADDR'], get_casper_code())
    state.set_code(casper_config['RLP_DECODER_ADDR'], get_rlp_decoder_code())
    state.set_code(casper_config['HASH_WITHOUT_BLOOM_ADDR'], get_hash_without_ed_code())
    state.set_code(casper_config['SERENITY_HEADER_POST_FINALIZER'], get_finalizer_code())
    state.set_code(casper_config['METROPOLIS_STATEROOT_STORE'], casper_config['SERENITY_GETTER_CODE'])
    state.set_code(casper_config['METROPOLIS_BLOCKHASH_STORE'], casper_config['SERENITY_GETTER_CODE'])

    ct = get_casper_ct()

    # Set genesis time, and initialize epoch number
    t = Transaction(0, 0, 10**8, casper_config['CASPER_ADDR'], 0, ct.encode('initialize', [timestamp, epoch_length, 0, 4712388]))
    apply_transaction(state, t)

    # Add validators
    for i, (vcode, deposit_size, randao_commitment) in enumerate(validators):
        state.set_balance(utils.int_to_addr(1), deposit_size)
        t = Transaction(i, 0, 10**8, casper_config['CASPER_ADDR'], deposit_size,
                        ct.encode('deposit', [vcode, randao_commitment]))
        t._sender = utils.int_to_addr(1)
        success = apply_transaction(state, t)
        assert success

    # Start the first epoch
    t = Transaction(0, 0, 10**8, casper_config['CASPER_ADDR'], 0, ct.encode('newEpoch', [0]))
    t._sender = casper_config['CASPER_ADDR']
    apply_transaction(state, t)

    assert call_casper(state, 'getEpoch', []) == 0
    assert call_casper(state, 'getTotalDeposits', []) == sum([d for a,d,r in validators])
    state.commit()

    return state
