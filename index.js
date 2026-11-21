import { timingSafeEqual } from 'node:crypto'

export const name = 'nginx-authentication'
export const inject = ['connection', 'connection.authentication']

const HEADER_NAME = 'x-dsh-proxy-auth'
const SECRET_ENV = 'DSH_PROXY_AUTH_SECRET'

function requestHeader(headers) {
  if (headers instanceof Headers) return headers.get(HEADER_NAME) ?? undefined
  const value = headers[HEADER_NAME]
  return typeof value === 'string' ? value : undefined
}

function secretsEqual(actual, expected) {
  const actualBytes = Buffer.from(actual, 'utf8')
  const expectedBytes = Buffer.from(expected, 'utf8')
  return actualBytes.byteLength === expectedBytes.byteLength
    && timingSafeEqual(actualBytes, expectedBytes)
}

export function apply(ctx) {
  const expected = process.env[SECRET_ENV]
  if (expected === undefined || Buffer.byteLength(expected, 'utf8') < 32) {
    throw new Error(`${name}: ${SECRET_ENV} must contain at least 32 bytes`)
  }

  const peer = ctx.connection.createPeer({ principal: { kind: 'owner' } })
  ctx.connection.authentication.register({
    authenticate(request) {
      const actual = requestHeader(request.headers)
      return actual !== undefined && secretsEqual(actual, expected) ? peer : undefined
    },
  })
}
