import time
import gevent
from devp2p.service import BaseService
from ethereum.casper_utils import call_casper

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

    @property
    def active(self):
        return self.app.config['validator']['activated']

    def create_next_block(self, block):
        pass

    def _run(self):
        while True:
            print time.time()
            self.next_validator()
            gevent.sleep(1)

    def next_validator(self):
        v = call_casper(self.state, 'getValidatorCount', [2])
        print "validators count at 256: ", v
        v = call_casper(self.state, 'getValidator', [0])
        print "next validator: ", v

    @property
    def state(self):
        return self.app.services.chain.chain.state

    def stop(self):
        super(ValidatorService, self).stop()

