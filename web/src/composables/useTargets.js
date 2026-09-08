import { ref } from 'vue'
import { getTargets } from '../api'

// Default labels used as a fallback before the API responds or if it fails.
const defaultTargetLabels = {
  mihomo: 'Clash / Mihomo',
  clash: 'Clash',
  stash: 'Stash',
  surge: 'Surge',
  'surge-mac': 'Surge Mac',
  surfboard: 'Surfboard',
  loon: 'Loon',
  shadowrocket: 'Shadowrocket',
  qx: 'Quantumult X',
  'sing-box': 'sing-box',
  v2ray: 'V2Ray',
  egern: 'Egern',
  json: 'JSON',
  uri: '通用链接 (URI)',
}

// Module-level shared state — loaded once, shared across all views.
const targets = ref(Object.keys(defaultTargetLabels))
const targetLabels = ref({ ...defaultTargetLabels })
let loaded = false

export function useTargets() {
  async function loadTargets() {
    if (loaded) return
    try {
      const { data } = await getTargets()
      if (Array.isArray(data) && data.length) {
        if (typeof data[0] === 'string') {
          // Legacy API: flat string array
          targets.value = data
        } else {
          // Structured API: [{name, label}]
          targets.value = data.map((t) => t.name)
          const labels = {}
          data.forEach((t) => {
            labels[t.name] = t.label
          })
          targetLabels.value = labels
        }
        loaded = true
      }
    } catch {
      // keep defaults on error
    }
  }

  function targetLabel(t) {
    return targetLabels.value[t] || t
  }

  return { targets, targetLabels, loadTargets, targetLabel }
}
