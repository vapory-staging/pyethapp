from ethereum import utils
from ethereum.casper_utils import RandaoManager

num_participants = 3

casper_genesis = {
    "privkeys": [utils.sha3(str(i)) for i in range(num_participants)],
    "randaos": [RandaoManager(utils.sha3(str(i))) for i in range(num_participants)],
    "deposit_sizes": [256, 256, 128]
}
casper_genesis["addresses"] = [utils.privtoaddr(k) for k in casper_genesis["privkeys"]]

