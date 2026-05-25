import { useEffect } from 'react'

function hashElement(): HTMLElement | null {
  if (typeof window === 'undefined') return null
  const raw = window.location.hash.slice(1)
  if (!raw) return null
  try {
    return document.getElementById(decodeURIComponent(raw))
  } catch {
    return document.getElementById(raw)
  }
}

export function useHashScroll(): void {
  useEffect(() => {
    if (typeof window === 'undefined') return undefined

    let frame = 0
    let timeout = 0
    const scrollNow = () => hashElement()?.scrollIntoView({ block: 'start' })
    const scroll = () => {
      window.cancelAnimationFrame(frame)
      window.clearTimeout(timeout)
      scrollNow()
      frame = window.requestAnimationFrame(scrollNow)
      timeout = window.setTimeout(scrollNow, 100)
    }

    scroll()
    window.addEventListener('hashchange', scroll)
    return () => {
      window.cancelAnimationFrame(frame)
      window.clearTimeout(timeout)
      window.removeEventListener('hashchange', scroll)
    }
  }, [])
}
