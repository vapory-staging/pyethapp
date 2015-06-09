from ethereum import utils
import random, rlp, sys
try:
    from urllib.request import build_opener
except:
    from urllib2 import build_opener


# Makes a request to a given URL (first arg) and optional params (second arg)
def make_request(*args):
    opener = build_opener()
    opener.addheaders = [('User-agent',
                          'Mozilla/5.0'+str(random.randrange(1000000)))]
    try:
        return opener.open(*args).read().strip()
    except Exception as e:
        try:
            p = e.read().strip()
        except:
            p = e
        raise Exception(p)


def warn_invalid(block):
    try:
        make_request('http://badblocks.ethdev.com', utils.encode_hex(rlp.encode(block)))
    except:
        sys.stderr.write('Failed to connect to badblocks.ethdev.com\n')
