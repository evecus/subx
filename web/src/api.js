import axios from 'axios'

// Relative to the page URL so the panel works under a secret path prefix
// (the backend `path` env variable); import.meta.env.BASE_URL is './'.
const API_BASE = import.meta.env.BASE_URL + 'api'
const api = axios.create({ baseURL: API_BASE, timeout: 30000 })

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401 && !location.hash.includes('/login')) {
      localStorage.removeItem('token')
      location.hash = '#/login'
    }
    return Promise.reject(err)
  },
)

export function login(username, password) {
  return api.post('/login', { username, password })
}

export function listSubs() {
  return api.get('/subs')
}

export function createSub(data) {
  return api.post('/subs', data)
}

export function getSub(name) {
  return api.get(`/sub/${encodeURIComponent(name)}`)
}

export function patchSub(name, data) {
  return api.patch(`/sub/${encodeURIComponent(name)}`, data)
}

export function deleteSub(name) {
  return api.delete(`/sub/${encodeURIComponent(name)}`)
}

export function updateSub(name) {
  return api.post(`/sub/${encodeURIComponent(name)}/update`)
}

export function nodeInfo(name) {
  return api.get(`/node-info/${encodeURIComponent(name)}`)
}

export function listCollections() {
  return api.get('/collections')
}

export function createCollection(data) {
  return api.post('/collections', data)
}

export function getCollection(name) {
  return api.get(`/col/${encodeURIComponent(name)}`)
}

export function patchCollection(name, data) {
  return api.patch(`/col/${encodeURIComponent(name)}`, data)
}

export function deleteCollection(name) {
  return api.delete(`/col/${encodeURIComponent(name)}`)
}

export function listFiles() {
  return api.get('/files')
}

export function createFile(data) {
  return api.post('/files', data)
}

export function getFile(name) {
  return api.get(`/file/${encodeURIComponent(name)}`)
}

export function patchFile(name, data) {
  return api.patch(`/file/${encodeURIComponent(name)}`, data)
}

export function deleteFile(name) {
  return api.delete(`/file/${encodeURIComponent(name)}`)
}

export function getFileRawUrl(name) {
  const token = localStorage.getItem('token') || ''
  return `${API_BASE}/file/${encodeURIComponent(name)}/raw?token=${encodeURIComponent(token)}`
}

export function listTokens() {
  return api.get('/tokens')
}

export function createToken(data) {
  return api.post('/token', data)
}

export function deleteToken(token) {
  return api.delete(`/token/${encodeURIComponent(token)}`)
}

export function getTargets() {
  return api.get('/targets')
}

export function getSettings() {
  return api.get('/settings')
}

export function patchSettings(data) {
  return api.patch('/settings', data)
}

export default api
