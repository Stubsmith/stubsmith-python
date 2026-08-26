#!/usr/bin/env python3
# Simple Python example to replay a fixture file using requests
import json
import requests

with open('fixtures/example-capture-get.json') as f:
    fx = json.load(f)

resp = requests.request(fx.get('method','GET'), fx['url'], headers=fx.get('headers',{}), json=fx.get('body'))
print('Status', resp.status_code)
print(resp.text[:500])
