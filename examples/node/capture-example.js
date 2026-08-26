#!/usr/bin/env node
// Simple capture example: perform an HTTP request and write a fixture JSON
const fs = require('fs');
const fetch = global.fetch || require('node-fetch');

(async ()=>{
  const res = await fetch('https://httpbin.org/get?example=1');
  const body = await res.json();
  const fixture = {
    name: 'example-capture-get',
    method: 'GET',
    url: 'https://httpbin.org/get?example=1',
    headers: {'Accept': 'application/json'},
    body: null
  };
  fs.writeFileSync('fixtures/example-capture-get.json', JSON.stringify(fixture, null, 2));
  console.log('Wrote fixtures/example-capture-get.json');
})();
