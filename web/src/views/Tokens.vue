<template>
  <div class="page-card">
    <div class="toolbar">
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>新建分享
      </el-button>
      <el-button @click="load">
        <el-icon><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <el-table :data="tokens" v-loading="loading" stripe class="desktop-table">
      <el-table-column prop="type" label="类型" width="90">
        <template #default="{ row }">
          <el-tag size="small" :type="typeTagStyle(row.type)">{{ typeLabel(row.type) }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="name" label="目标名称" min-width="140" />
      <el-table-column prop="token" label="Token" min-width="200" show-overflow-tooltip />
      <el-table-column label="模式" width="110">
        <template #default="{ row }">
          <el-tag size="small">{{ row.mode || 'duration' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="已用/限制" width="110">
        <template #default="{ row }">
          <span>{{ row.usedCount ?? 0 }} / {{ row.count || '-' }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="300" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="handleAction(row, 'copy')">复制链接</el-button>
          <el-button size="small" @click="handleAction(row, 'preview')">预览</el-button>
          <el-button size="small" @click="handleAction(row, 'download')">下载</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="mobile-cards" v-loading="loading">
      <div v-for="row in tokens" :key="row.token" class="mobile-card">
        <div class="mobile-card-top">
          <el-tag size="small" :type="typeTagStyle(row.type)">{{ typeLabel(row.type) }}</el-tag>
          <span class="mobile-card-name">{{ row.name }}</span>
          <el-tag size="small">{{ row.mode || 'duration' }}</el-tag>
        </div>
        <div class="mobile-card-row">
          <span class="mobile-card-label">Token</span>
          <span class="mobile-card-value ellipsis">{{ row.token }}</span>
        </div>
        <div class="mobile-card-row">
          <span class="mobile-card-label">已用/限制</span>
          <span class="mobile-card-value">{{ row.usedCount ?? 0 }} / {{ row.count || '-' }}</span>
        </div>
        <div class="mobile-card-actions">
          <el-button size="small" @click="handleAction(row, 'copy')">复制链接</el-button>
          <el-button size="small" @click="handleAction(row, 'preview')">预览</el-button>
          <el-button size="small" @click="handleAction(row, 'download')">下载</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </div>
      </div>
      <el-empty v-if="!loading && !tokens.length" description="暂无分享" />
    </div>

    <el-dialog v-model="dialog" title="新建分享" width="560px" destroy-on-close class="responsive-dialog">
      <el-form label-width="90px">
        <el-form-item label="类型">
          <el-radio-group v-model="form.type" @change="onTypeChange">
            <el-radio-button label="sub">订阅</el-radio-button>
            <el-radio-button label="col">组合订阅</el-radio-button>
            <el-radio-button label="file">文件</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="目标">
          <el-select v-model="form.name" filterable style="width:100%">
            <el-option v-for="s in targetOptionsForType(form.type)" :key="s.name" :label="s.name" :value="s.name" />
          </el-select>
        </el-form-item>
        <el-form-item label="模式">
          <el-radio-group v-model="form.mode">
            <el-radio-button label="duration">时长</el-radio-button>
            <el-radio-button label="count">次数</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.mode === 'duration'" label="有效期">
          <el-select v-model="form.seconds">
            <el-option :value="3600" label="1 小时" />
            <el-option :value="86400" label="1 天" />
            <el-option :value="604800" label="7 天" />
            <el-option :value="2592000" label="30 天" />
            <el-option :value="15552000" label="半年" />
            <el-option :value="31536000" label="一年" />
            <el-option :value="0" label="永久" />
          </el-select>
        </el-form-item>
        <el-form-item v-if="form.mode === 'count'" label="次数">
          <el-input-number v-model="form.count" :min="1" />
        </el-form-item>
      </el-form>
      <el-alert v-if="form.type !== 'file'" type="info" :closable="false" style="margin-top:4px">
        生成后可在下方"预览 / 下载 / 复制链接"时再选择客户端格式；分享链接末尾的 <code>target=</code> 参数决定输出格式，客户端订阅时填这个链接即可。
      </el-alert>
      <el-alert v-else type="info" :closable="false" style="margin-top:4px">
        文件分享无需选择客户端格式，生成后可直接复制链接、在线预览（原始文本）或下载。
      </el-alert>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">生成</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="targetDialog" title="选择客户端类型" width="420px" class="responsive-dialog">
      <div class="target-grid">
        <el-button
          v-for="t in targets"
          :key="t"
          class="target-btn"
          @click="confirmTarget(t)"
        >{{ targetLabel(t) }}</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listTokens, createToken, deleteToken, listSubs, listCollections, listFiles } from '../api'
import { useTargets } from '../composables/useTargets'

const tokens = ref([])
const subs = ref([])
const cols = ref([])
const files = ref([])
const loading = ref(false)
const saving = ref(false)
const dialog = ref(false)
const targetDialog = ref(false)
const pendingRow = ref(null)
const pendingAction = ref('')
const form = ref({ type: 'sub', name: '', mode: 'duration', seconds: 604800, count: 10 })

const typeLabels = { sub: '订阅', col: '组合订阅', file: '文件' }
const typeTagStyles = { sub: 'success', col: 'warning', file: 'info' }

function typeLabel(t) {
  return typeLabels[t] || t
}

function typeTagStyle(t) {
  return typeTagStyles[t] || ''
}

function targetOptionsForType(type) {
  if (type === 'sub') return subs.value
  if (type === 'file') return files.value
  return cols.value
}

function onTypeChange() {
  const opts = targetOptionsForType(form.value.type)
  form.value.name = opts[0]?.name || ''
}

const { targets, targetLabel, loadTargets } = useTargets()

function shareKind(type) {
  if (type === 'file') return 'file'
  if (type === 'col') return 'col'
  return 'sub'
}

function shareUrl(row, target, extra = '') {
  const kind = shareKind(row.type)
  const base = location.origin + location.pathname.replace(/\/[^/]*$/, '')
  const targetParam = kind === 'file' ? '' : `&target=${encodeURIComponent(target || 'mihomo')}`
  return `${base}/share/${kind}/${encodeURIComponent(row.name)}?token=${row.token}${targetParam}${extra}`
}

async function copyText(text) {
  if (navigator.clipboard && window.isSecureContext) {
    await navigator.clipboard.writeText(text)
    return
  }
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.opacity = '0'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  const ok = document.execCommand('copy')
  document.body.removeChild(ta)
  if (!ok) throw new Error('copy failed')
}

// File shares have no client-format concept, so they skip the target-picker
// dialog and act immediately.
async function handleAction(row, action) {
  if (row.type === 'file') {
    await runAction(row, action, '')
    return
  }
  askTarget(row, action)
}

function askTarget(row, action) {
  pendingRow.value = row
  pendingAction.value = action
  targetDialog.value = true
}

async function runAction(row, action, target) {
  if (action === 'copy') {
    const url = shareUrl(row, target)
    try {
      await copyText(url)
      ElMessage.success('分享链接已复制')
    } catch {
      ElMessage.warning('复制失败，请手动复制：' + url)
    }
  } else if (action === 'preview') {
    window.open(shareUrl(row, target, '&preview=1'), '_blank')
  } else if (action === 'download') {
    window.open(shareUrl(row, target), '_blank')
  }
}

async function confirmTarget(target) {
  const row = pendingRow.value
  const action = pendingAction.value
  targetDialog.value = false
  if (!row) return
  await runAction(row, action, target)
}

async function load() {
  loading.value = true
  try {
    const [t, s, c, f] = await Promise.all([listTokens(), listSubs(), listCollections(), listFiles(), loadTargets()])
    tokens.value = t.data
    subs.value = s.data
    cols.value = c.data
    files.value = f.data
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  form.value = { type: 'sub', name: subs.value[0]?.name || '', mode: 'duration', seconds: 604800, count: 10 }
  dialog.value = true
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请选择分享目标')
    return
  }
  saving.value = true
  try {
    const permanent = form.value.mode === 'duration' && form.value.seconds === 0
    const payload = {
      type: form.value.type,
      name: form.value.name,
      mode: form.value.mode,
      seconds: form.value.seconds,
      permanent,
      count: form.value.count,
    }
    const { data } = await createToken(payload)
    ElMessage.success('分享已生成')
    dialog.value = false
    await load()
    try {
      await copyText(shareUrl(data, 'mihomo'))
      ElMessage.success('分享链接已复制')
    } catch {
      // ignore clipboard errors here; user can still copy from the table
    }
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '生成失败')
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确认删除令牌 ${row.token}？`, '提示', { type: 'warning' })
    await deleteToken(row.token)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.message || '删除失败')
  }
}

onMounted(load)
</script>

<style scoped>
.page-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-sm);
  padding: 20px;
}
.toolbar { margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap; }
.target-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 10px;
}
.target-btn {
  width: 100%;
  justify-content: center;
  margin-left: 0 !important;
}

.mobile-cards { display: none; }
.mobile-card {
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-md);
  padding: 12px;
  margin-bottom: 10px;
}
.mobile-card-top {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
  flex-wrap: wrap;
}
.mobile-card-name {
  font-weight: 600;
  color: var(--text-strong);
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.mobile-card-row {
  display: flex;
  justify-content: space-between;
  gap: 10px;
  font-size: 13px;
  padding: 3px 0;
}
.mobile-card-label { color: var(--text-muted); flex-shrink: 0; }
.mobile-card-value { color: var(--text-body); text-align: right; }
.mobile-card-value.ellipsis {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  min-width: 0;
}
.mobile-card-actions {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-top: 10px;
}

@media (max-width: 768px) {
  .page-card { padding: 14px; }
  .desktop-table { display: none; }
  .mobile-cards { display: block; }
  .target-grid { grid-template-columns: 1fr; }
}
</style>
