export function navigate(to: string) {
  if (typeof window === 'undefined') return
  if (window.location.pathname === to) return
  window.history.pushState({}, '', to)
  window.dispatchEvent(new PopStateEvent('popstate'))
}
