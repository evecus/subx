<template>
  <el-container class="layout">
    <div v-if="mobileNavOpen" class="aside-overlay" @click="mobileNavOpen = false"></div>
    <el-aside width="220px" class="aside" :class="{ 'aside-open': mobileNavOpen }">
      <div class="logo">
        <span class="logo-dot"></span>
        <span class="logo-text">Sub-Store</span>
      </div>
      <el-menu :default-active="$route.path" router class="nav-menu" @select="mobileNavOpen = false">
        <el-menu-item index="/subs">
          <el-icon><Connection /></el-icon>
          <span>订阅管理</span>
        </el-menu-item>
        <el-menu-item index="/collections">
          <el-icon><FolderOpened /></el-icon>
          <span>组合订阅</span>
        </el-menu-item>
        <el-menu-item index="/files">
          <el-icon><Document /></el-icon>
          <span>文件管理</span>
        </el-menu-item>
        <el-menu-item index="/tokens">
          <el-icon><Key /></el-icon>
          <span>分享管理</span>
        </el-menu-item>
        <el-menu-item index="/settings">
          <el-icon><Setting /></el-icon>
          <span>设置</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container class="content-container">
      <el-header class="header">
        <div class="header-left">
          <span class="nav-toggle" @click="mobileNavOpen = true">
            <el-icon><Menu /></el-icon>
          </span>
          <div class="header-title">{{ pageTitle }}</div>
        </div>
        <el-dropdown @command="onCommand">
          <span class="user">
            <span class="avatar">{{ (username || '?').charAt(0).toUpperCase() }}</span>
            <span class="username-text">{{ username }}</span><el-icon><ArrowDown /></el-icon>
          </span>
          <template #dropdown>
            <el-dropdown-menu>
              <el-dropdown-item command="logout">退出登录</el-dropdown-item>
            </el-dropdown-menu>
          </template>
        </el-dropdown>
      </el-header>
      <el-main class="main">
        <router-view v-slot="{ Component }">
          <transition name="fade-slide" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </el-main>
    </el-container>
  </el-container>
</template>

<script setup>
import { ref, computed, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'

const route = useRoute()
const router = useRouter()
const username = localStorage.getItem('username') || ''
const mobileNavOpen = ref(false)

const titles = {
  '/subs': '订阅管理',
  '/files': '文件管理',
  '/collections': '组合订阅',
  '/tokens': '分享管理',
  '/settings': '设置',
}
const pageTitle = computed(() => titles[route.path] || 'Sub-Store')

watch(() => route.path, () => {
  mobileNavOpen.value = false
})

function onCommand(cmd) {
  if (cmd === 'logout') {
    localStorage.removeItem('token')
    localStorage.removeItem('username')
    router.push('/login')
  }
}
</script>

<style scoped>
.layout { height: 100%; }
.content-container { min-width: 0; }

.aside {
  background: var(--bg-surface);
  border-right: 1px solid var(--border-soft);
  padding: 0 12px;
  display: flex;
  flex-direction: column;
}

.aside-overlay { display: none; }

.nav-toggle {
  display: none;
  align-items: center;
  justify-content: center;
  width: 32px;
  height: 32px;
  border-radius: var(--radius-sm);
  color: var(--text-body);
  cursor: pointer;
  flex-shrink: 0;
}
.nav-toggle:hover { background: var(--bg-soft); }

.header-left {
  display: flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
}

.username-text {
  max-width: 120px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.logo {
  height: 64px;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 0 8px;
}
.logo-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  background: var(--brand-gradient);
  box-shadow: 0 0 0 5px rgba(99, 102, 241, 0.12);
}
.logo-text {
  font-size: 17px;
  font-weight: 800;
  letter-spacing: -0.02em;
  background: var(--brand-gradient);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}

.nav-menu { border-right: none; background: transparent; }
.nav-menu :deep(.el-menu-item) {
  height: 42px;
  line-height: 42px;
  border-radius: var(--radius-sm);
  margin-bottom: 4px;
  color: var(--text-body);
  font-weight: 500;
  transition: background-color 0.18s ease, color 0.18s ease, transform 0.18s ease;
}
.nav-menu :deep(.el-menu-item .el-icon) {
  color: var(--text-muted);
  transition: color 0.18s ease;
}
.nav-menu :deep(.el-menu-item:hover) {
  background: var(--bg-soft);
  transform: translateX(2px);
}
.nav-menu :deep(.el-menu-item.is-active) {
  background: var(--bg-soft);
  color: var(--brand-1);
  font-weight: 600;
}
.nav-menu :deep(.el-menu-item.is-active .el-icon) {
  color: var(--brand-1);
}

.header {
  display: flex; align-items: center; justify-content: space-between;
  border-bottom: 1px solid var(--border-soft);
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(10px);
  padding: 0 24px;
}
.header-title {
  font-size: 17px;
  font-weight: 700;
  color: var(--text-strong);
}
.user {
  cursor: pointer;
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--text-body);
  font-weight: 500;
  padding: 6px 10px 6px 6px;
  border-radius: 999px;
  transition: background-color 0.15s ease;
}
.user:hover { background: var(--bg-soft); }
.avatar {
  width: 26px;
  height: 26px;
  border-radius: 50%;
  background: var(--brand-gradient);
  color: #fff;
  font-size: 12px;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}
.main {
  background: var(--bg-page);
  padding: 24px;
}

.fade-slide-enter-active, .fade-slide-leave-active {
  transition: opacity 0.2s ease, transform 0.2s ease;
}
.fade-slide-enter-from {
  opacity: 0;
  transform: translateY(6px);
}
.fade-slide-leave-to {
  opacity: 0;
  transform: translateY(-6px);
}

@media (max-width: 768px) {
  .aside {
    position: fixed;
    top: 0;
    left: 0;
    bottom: 0;
    z-index: 1000;
    width: 240px !important;
    max-width: 80vw;
    transform: translateX(-100%);
    transition: transform 0.22s ease;
    box-shadow: var(--shadow-lg);
  }
  .aside.aside-open {
    transform: translateX(0);
  }
  .aside-overlay {
    display: block;
    position: fixed;
    inset: 0;
    background: rgba(15, 13, 30, 0.4);
    z-index: 999;
  }
  .nav-toggle {
    display: flex;
  }
  .header {
    padding: 0 12px;
  }
  .header-title {
    font-size: 15px;
  }
  .username-text {
    display: none;
  }
  .user {
    padding: 6px;
  }
  .main {
    padding: 12px;
  }
}
</style>
