import assert from 'node:assert/strict'
import { apply } from './index.js'

const secret = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
process.env.DSH_PROXY_AUTH_SECRET = secret

const peer = { signal: new AbortController().signal }
let provider
const ctx = {
  connection: {
    createPeer(options) {
      assert.deepEqual(options, { principal: { kind: 'owner' } })
      return peer
    },
    authentication: {
      register(value) {
        provider = value
      },
    },
  },
}

apply(ctx)
assert.equal(provider.authenticate({ headers: { 'x-dsh-proxy-auth': secret } }), peer)
assert.equal(provider.authenticate({ headers: new Headers({ 'X-DSH-Proxy-Auth': secret }) }), peer)
assert.equal(provider.authenticate({ headers: { 'x-dsh-proxy-auth': `${secret}x` } }), undefined)
assert.equal(provider.authenticate({ headers: { 'x-dsh-proxy-auth': ['duplicate', secret] } }), undefined)
assert.equal(provider.authenticate({ headers: {} }), undefined)

process.env.DSH_PROXY_AUTH_SECRET = 'short'
assert.throws(() => apply(ctx), /must contain at least 32 bytes/u)
