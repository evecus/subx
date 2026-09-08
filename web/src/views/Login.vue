<template>
  <div class="login-page">
    <div class="glow glow-1"></div>
    <div class="glow glow-2"></div>
    <el-card class="login-card">
      <div class="brand">
        <span class="brand-dot"></span>
        <div class="login-title">Sub-Store</div>
      </div>
      <div class="login-subtitle">订阅管理，简单又灵活</div>
      <el-form @submit.prevent="doLogin" label-position="top" class="login-form">
        <el-form-item label="账号">
          <el-input v-model="username" placeholder="请输入账号" size="large" />
        </el-form-item>
        <el-form-item label="密码">
          <el-input v-model="password" type="password" show-password placeholder="请输入密码" size="large" @keyup.enter="doLogin" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" :loading="loading" @click="doLogin" size="large" style="width:100%">登录</el-button>
        </el-form-item>
      </el-form>
    </el-card>
  </div>
</template>

<script setup>
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { login } from '../api'

const router = useRouter()
const username = ref('')
const password = ref('')
const loading = ref(false)

function handleToken(data) {
  localStorage.setItem('token', data.token)
  localStorage.setItem('username', data.username)
  ElMessage.success('登录成功')
  router.push('/subs')
}

async function doLogin() {
  loading.value = true
  try {
    const { data } = await login(username.value.trim(), password.value)
    handleToken(data)
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '登录失败')
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.login-page {
  height: 100%;
  position: relative;
  overflow: hidden;
  display: flex;
  align-items: center;
  justify-content: center;
  background: var(--bg-page);
  padding: 16px;
}
.glow {
  position: absolute;
  border-radius: 50%;
  filter: blur(70px);
  opacity: 0.35;
  pointer-events: none;
}
.glow-1 {
  width: 360px; height: 360px;
  top: -80px; left: -80px;
  background: radial-gradient(circle, #8b5cf6, transparent 70%);
}
.glow-2 {
  width: 420px; height: 420px;
  bottom: -120px; right: -100px;
  background: radial-gradient(circle, #06b6d4, transparent 70%);
}

.login-card {
  width: 380px;
  max-width: 100%;
  padding: 12px 8px;
  position: relative;
  z-index: 1;
}
.brand {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  margin-top: 4px;
}
.brand-dot {
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--brand-gradient);
  box-shadow: 0 0 0 6px rgba(99, 102, 241, 0.12);
}
.login-title {
  text-align: center;
  font-size: 22px;
  font-weight: 800;
  letter-spacing: -0.02em;
  background: var(--brand-gradient);
  -webkit-background-clip: text;
  background-clip: text;
  color: transparent;
}
.login-subtitle {
  text-align: center;
  color: var(--text-muted);
  font-size: 13px;
  margin: 6px 0 20px;
}
.login-form :deep(.el-form-item__label) {
  color: var(--text-body);
  font-weight: 500;
}
</style>
