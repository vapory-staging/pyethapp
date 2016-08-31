from ethereum import utils
from ethereum.casper_utils import RandaoManager, generate_validation_code

num_participants = 3

# ['044852b2a670ade5407e78fb2863c51de9fcb96542a07186fe3aeda6bb8a116d', 'c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6', 'ad7c5bef027816a800da1736444fb58a807ef4c9603b7848673f7e3a68eb14a5']
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

