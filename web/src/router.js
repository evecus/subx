import { createRouter, createWebHashHistory } from 'vue-router'

const routes = [
  { path: '/login', name: 'login', component: () => import('./views/Login.vue') },
  {
    path: '/',
    component: () => import('./views/Layout.vue'),
    children: [
      { path: '', redirect: '/subs' },
      { path: 'subs', name: 'subs', component: () => import('./views/Subs.vue') },
      { path: 'files', name: 'files', component: () => import('./views/Files.vue') },
      { path: 'collections', name: 'collections', component: () => import('./views/Collections.vue') },
      { path: 'tokens', name: 'tokens', component: () => import('./views/Tokens.vue') },
      { path: 'settings', name: 'settings', component: () => import('./views/Settings.vue') },
    ],
  },
]

const router = createRouter({
  history: createWebHashHistory(),
  routes,
})

router.beforeEach((to) => {
  const token = localStorage.getItem('token')
  if (to.name !== 'login' && !token) {
    return { name: 'login' }
  }
  if (to.name === 'login' && token) {
    return { name: 'subs' }
  }
})

export default router
