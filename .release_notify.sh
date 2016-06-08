#!/usr/bin/env sh
PAYLOAD="{\"text\": \"TEST: <https://pypi.python.org/pypi/pyethapp|pyethapp $TRAVIS_TAG> was released on pypi!\"}"
curl -s -X POST --data-urlencode "payload=$PAYLOAD" $SLACK_WEBHOOK_URL
