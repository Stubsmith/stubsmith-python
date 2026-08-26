#!/usr/bin/env node
// Simple Express middleware that posts captures to a StubSmith ingest endpoint
// Usage: set STUBSMITH_URL and API_KEY env vars, then add as middleware

const fetch = global.fetch || require('node-fetch');

function captureMiddleware(opts){
  const url = (opts && opts.url) || process.env.STUBSMITH_URL || 'http://localhost:3000/v1/captures';
  const key = (opts && opts.key) || process.env.STUBSMITH_API_KEY || process.env.API_KEY;
  return (req,res,next)=>{
    const start = Date.now();
    const chunks = [];
    req.on('data', c=> chunks.push(c));
    req.on('end', ()=>{});
    const onFinish = async ()=>{
      const duration = Date.now() - start;
      const body = (chunks.length>0) ? Buffer.concat(chunks).toString('utf8') : null;
      const payload = {
        source: 'express',
        method: req.method,
        url: req.originalUrl || req.url,
        headers: req.headers,
        body,
        status: res.statusCode,
        duration
      };
      try{
        await fetch(url, {method:'POST', body: JSON.stringify(payload), headers: { 'Content-Type':'application/json', 'Authorization': `Bearer ${key}` }});
      }catch(e){ /* ignore */ }
    };
    res.on('finish', onFinish);
    next();
  };
}

module.exports = captureMiddleware;
