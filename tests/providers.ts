import type { CryptoProvider } from '../src/provider.ts'
import { WebCryptoProvider } from '../src/providers/web.ts'

const inBrowser = typeof window !== 'undefined'

/**
 * On Node both providers run; in the browser only the web provider. The Node provider is imported
 * only on Node, so the browser bundle never loads `node:crypto`.
 */
async function loadProviders(): Promise<CryptoProvider[]> {
  if (inBrowser) return [new WebCryptoProvider()]
  const { NodeCryptoProvider } = await import('../src/providers/node.ts')
  return [new NodeCryptoProvider(), new WebCryptoProvider()]
}

export const providers = await loadProviders()
