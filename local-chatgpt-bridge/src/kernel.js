const BASE = 'https://api.onkernel.com'

function requireApiKey() {
  const key = process.env.KERNEL_API_KEY
  if (!key) throw new Error('KERNEL_API_KEY environment variable is not set')
  return key
}

async function kernelPost(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${requireApiKey()}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Kernel API POST ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

async function kernelGet(path) {
  const res = await fetch(`${BASE}${path}`, {
    headers: { Authorization: `Bearer ${requireApiKey()}` },
  })
  if (!res.ok) {
    const text = await res.text().catch(() => '')
    throw new Error(`Kernel API GET ${path} → ${res.status}: ${text}`)
  }
  return res.json()
}

export async function acquireBrowser(poolName, acquireTimeoutSeconds = 30) {
  return kernelPost(`/browser_pools/${poolName}/acquire`, {
    acquire_timeout_seconds: acquireTimeoutSeconds,
  })
}

export async function releaseBrowser(poolName, sessionId, reuse = true) {
  return kernelPost(`/browser_pools/${poolName}/release`, {
    session_id: sessionId,
    reuse,
  })
}

export async function listPools() {
  return kernelGet('/browser_pools')
}
