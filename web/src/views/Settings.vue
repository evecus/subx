<template>
  <el-card class="settings-card">
    <template #header>
      <div class="settings-header">
        <div class="settings-title">全局设置</div>
        <div class="settings-subtitle">配置默认下载行为与代理参数</div>
      </div>
    </template>
    <el-form label-position="top" style="max-width: 560px">
      <el-form-item label="默认 User-Agent">
        <el-input v-model="settings.defaultUserAgent" placeholder="下载订阅时的默认 UA" />
      </el-form-item>
      <el-form-item label="默认超时(秒)">
        <el-input-number v-model="settings.defaultTimeout" :min="1" :max="300" style="width: 100%" />
      </el-form-item>
      <el-form-item label="默认代理">
        <el-input v-model="settings.defaultProxy" placeholder="默认代理（预留）" />
      </el-form-item>
      <el-form-item label="缓存阈值">
        <el-input-number v-model="settings.cacheThreshold" :min="0" style="width: 100%" />
      </el-form-item>
      <el-form-item label="GitHub 代理">
        <el-input v-model="settings.githubProxy" placeholder="https://ghproxy.com/" />
      </el-form-item>
      <el-form-item>
        <el-button type="primary" :loading="saving" @click="save">保存设置</el-button>
      </el-form-item>
    </el-form>
  </el-card>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import { getSettings, patchSettings } from '../api'

const settings = ref({})
const saving = ref(false)

async function load() {
  try {
    const { data } = await getSettings()
    settings.value = { defaultUserAgent: '', defaultTimeout: 30, defaultProxy: '', cacheThreshold: 0, githubProxy: '', ...data }
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  }
}

async function save() {
  saving.value = true
  try {
    await patchSettings(settings.value)
    ElMessage.success('设置已保存')
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '保存失败')
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.settings-card :deep(.el-card__header) { padding-bottom: 14px; }
.settings-title { font-size: 16px; font-weight: 700; color: var(--text-strong); }
.settings-subtitle { font-size: 12px; color: var(--text-muted); margin-top: 4px; }
.settings-card :deep(.el-form-item__label) { font-weight: 500; color: var(--text-body); }

@media (max-width: 768px) {
  .settings-card :deep(.el-card__body) { padding: 14px; }
}
</style>
