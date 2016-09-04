import time
import gevent
from devp2p.service import BaseService
from ethereum.slogging import get_logger
from ethereum.utils import privtoaddr, remove_0x_head, decode_hex
from ethereum.casper_utils import generate_validation_code, find_indices, call_casper, get_skips_and_block_making_time, get_timestamp, sign_block, RandaoManager
from ethereum.block_creation import make_head_candidate

log = get_logger('validator')

BLOCK_TIME = 3

class ValidatorService(BaseService):

    name = 'validator'
    default_config = dict(validator=dict(
        activated=False,
        privkey='',
        deposit_size=0,
        seed=''
    ))

    def __init__(self, app):
        super(ValidatorService, self).__init__(app)
        self.config = app.config
        self.seed = decode_hex(remove_0x_head(self.config['validator']['seed']))
        self.randao = RandaoManager(self.seed)

    @property
    def active(self):
        return self.app.config['validator']['activated']

    def _run(self):
        while True:
            if self.active:
                skip_count, timestamp = get_skips_and_block_making_time(self.chain, self.get_indices())
                if skip_count == 0:
                    wait = timestamp - time.time()
                    if wait > 0:
                        gevent.sleep(wait)
                    blk = self.make_block(skip_count)
                    delay = time.time() - blk.timestamp
                    log.info("block created", height=blk.header.number, delay=delay)
                    assert self.app.services.chain.add_mined_block(blk)
                else:
                    log.info("not my turn: ", skip_count=skip_count)
                    gevent.sleep(BLOCK_TIME)

    def make_block(self, skips):
        h = make_head_candidate(self.chain,
                                self.app.services.chain.transaction_queue,
                                timestamp=get_timestamp(self.chain, skips))
        privkey = self.config['validator']['privkey']
        indices = self.get_indices()[0:2]
        randao = call_casper(self.state, 'getRandao', indices)
        randao_parent = self.randao.get_parent(randao)
        return sign_block(h, privkey, randao_parent, indices, skips)

    def is_my_turn(self):
        indices = self.get_indices()
        log.debug("my indices: ", indices)
        if not indices[2]: # not active
            return False
        next_indices = self.get_next_validator()
        log.debug("next validator indices: ", next_indices)
        if indices[0:2] == next_indices:
            return True
        return False

    def get_indices(self):
        addr = privtoaddr(self.config['validator']['privkey'])
        vcode = generate_validation_code(addr)
        return find_indices(self.state, vcode)

    def get_next_validator(self):
        return call_casper(self.state, 'getValidator', [0])

    @property
    def state(self):
        return self.chain.state

    @property
    def chain(self):
        return self.app.services.chain.chain

    def stop(self):
        super(ValidatorService, self).stop()

