"""
Essential parts borrowed from https://github.com/ipython/ipython/pull/1654
"""
import signal
from devp2p.service import BaseService
import gevent
from gevent.event import Event
import IPython
import IPython.core.shellapp
from IPython.lib.inputhook import inputhook_manager, stdin_ready
from ethereum import slogging
from ethereum.transactions import Transaction
from ethereum.utils import denoms
from ethereum import processblock
from rpc_client import ABIContract, address20

import sys
GUI_GEVENT = 'gevent'


def inputhook_gevent():
    while not stdin_ready():
        gevent.sleep(0.05)
    return 0


@inputhook_manager.register('gevent')
class GeventInputHook(object):

    def __init__(self, manager):
        self.manager = manager

    def enable(self, app=None):
        """Enable event loop integration with gevent.
        Parameters
        ----------
        app : ignored
            Ignored, it's only a placeholder to keep the call signature of all
            gui activation methods consistent, which simplifies the logic of
            supporting magics.
        Notes
        -----
        This methods sets the PyOS_InputHook for gevent, which allows
        gevent greenlets to run in the background while interactively using
        IPython.
        """
        self.manager.set_inputhook(inputhook_gevent)
        self._current_gui = GUI_GEVENT
        return app

    def disable(self):
        """Disable event loop integration with gevent.
        This merely sets PyOS_InputHook to NULL.
        """
        self.manager.clear_inputhook()


# ipython needs to accept "--gui gevent" option
IPython.core.shellapp.InteractiveShellApp.gui.values += ('gevent',)


class Console(BaseService):

    """A service starting an interactive ipython session when receiving the
    SIGSTP signal (e.g. via keyboard shortcut CTRL-Z).
    """

    name = 'console'

    def __init__(self, app):
        super(Console, self).__init__(app)
        self.interrupt = Event()
        if not app.start_console:
            gevent.signal(signal.SIGINT, self.interrupt.set)
        self.console_locals = {}
        if app.start_console:
            self.start()
            self.interrupt.set()

    def _stop_app(self):
        try:
            self.app.stop()
        except gevent.GreenletExit:
            pass

    def start(self):
        super(Console, self).start()

        class Eth(object):
            """
            convenience object to interact with the live chain
            """
            app = self.app
            services = self.app.services
            stop = self._stop_app
            chainservice = self.app.services.chain
            chain = chainservice.chain
            latest = head = property(lambda s: s.chain.head)
            pending = head_candidate = property(lambda s: s.chain.head_candidate)
            coinbase = self.app.services.accounts.coinbase

            def __init__(this, app):
                this.app = app

            def transact(this, to, value=0, data='', sender=None,
                         startgas=25000, gasprice=10*denoms.szabo):
                sender = address20(sender or this.coinbase)
                to = address20(to)
                nonce = this.pending.get_nonce(sender)
                tx = Transaction(nonce, gasprice, startgas, to, value, data)
                this.app.services.accounts.sign_tx(sender, tx)
                assert tx.sender == sender
                this.chainservice.add_transaction(tx)
                return tx

            def call(this, to, value=0, data='',  sender=None,
                     startgas=25000, gasprice=10*denoms.szabo):
                sender = address20(sender or this.coinbase)
                to = address20(to)
                block = this.head_candidate
                state_root_before = block.state_root
                assert block.has_parent()
                # rebuild block state before finalization
                parent = block.get_parent()
                test_block = block.init_from_parent(parent, block.coinbase,
                                                    timestamp=block.timestamp)
                for tx in block.get_transactions():
                    success, output = processblock.apply_transaction(test_block, tx)
                    assert success

                # apply transaction
                nonce = test_block.get_nonce(sender)
                tx = Transaction(nonce, gasprice, startgas, to, value, data)
                tx.sender = sender
                try:
                    success, output = processblock.apply_transaction(test_block, tx)
                except processblock.InvalidTransaction as e:
                    success = False
                assert block.state_root == state_root_before
                if success:
                    return output
                else:
                    return False

            def find_transaction(this, tx):
                try:
                    t, blk, idx = this.chain.index.get_transaction(tx.hash)
                except:
                    return {}
                return dict(tx=t, block=blk, index=idx)

            def new_contract(this, abi, address, sender=None):
                return ABIContract(sender or this.coinbase, abi, address, this.call, this.transact)

            def block_from_rlp(this, rlp_data):
                from eth_protocol import TransientBlock
                import rlp
                l = rlp.decode_lazy(rlp_data)
                return TransientBlock(l).to_block(this.chain.blockchain)

        try:
            from ethereum._solidity import solc_wrapper
        except ImportError:
            solc_wrapper = None
            pass

        try:
            import serpent
        except ImportError:
            serpent = None
            pass

        self.console_locals = dict(eth=Eth(self.app), solidity=solc_wrapper, serpent=serpent,
                                   denoms=denoms)

    def _run(self):
        self.interrupt.wait()
        print('\n' * 3)
        print("Entering Console")
        print("Tip: use loglevel `-l:error` to avoid logs")
        print(">> help(eth)")
        IPython.start_ipython(argv=['--gui', 'gevent'], user_ns=self.console_locals)
        self.interrupt.clear()

        sys.exit(0)
