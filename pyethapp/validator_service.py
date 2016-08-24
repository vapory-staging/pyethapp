import time
import gevent
from devp2p.service import BaseService

class ValidatorService(BaseService):

    name = 'validator'
    default_config = dict(validator=dict(
        activated=False,
        privkey='',
        deposit_size=0
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
            gevent.sleep(1)

    def stop(self):
        super(ValidatorService, self).stop()

