<template>
  <div class="page-card">
    <div class="toolbar">
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>新建订阅
      </el-button>
      <el-button @click="load">
        <el-icon><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <el-table :data="subs" v-loading="loading" stripe class="desktop-table">
      <el-table-column prop="name" label="名称" min-width="140" />
      <el-table-column label="类型" width="90">
        <template #default="{ row }">
          <el-tag size="small">{{ row.source || 'remote' }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column prop="url" label="URL" min-width="220" show-overflow-tooltip />
      <el-table-column label="操作" width="260" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="mobile-cards" v-loading="loading">
      <div v-for="row in subs" :key="row.name" class="mobile-card">
        <div class="mobile-card-top">
          <span class="mobile-card-name">{{ row.name }}</span>
          <el-tag size="small">{{ row.source || 'remote' }}</el-tag>
        </div>
        <div class="mobile-card-row" v-if="row.url">
          <span class="mobile-card-label">URL</span>
          <span class="mobile-card-value ellipsis">{{ row.url }}</span>
        </div>
        <div class="mobile-card-actions">
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </div>
      </div>
      <el-empty v-if="!loading && !subs.length" description="暂无订阅" />
    </div>

    <el-dialog v-model="dialog" :title="editing ? '编辑订阅' : '新建订阅'" width="640px" destroy-on-close class="responsive-dialog">
      <el-form label-width="90px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="订阅名称" />
        </el-form-item>
        <el-form-item label="类型">
          <el-radio-group v-model="form.sourceType">
            <el-radio-button label="remote">远程</el-radio-button>
            <el-radio-button label="local">本地</el-radio-button>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="form.sourceType === 'remote'" label="URL">
          <el-input v-model="form.url" placeholder="订阅链接" />
        </el-form-item>
        <el-form-item v-if="form.sourceType === 'remote'" label="定时更新">
          <el-input v-model="form.updateCron" placeholder="cron 表达式，例如 0 0 * * *（留空则不定时更新）" />
          <div v-if="form.updateCron && !cronValid" class="field-hint field-hint-error">
            格式不正确，应为标准 5 段 cron：分 时 日 月 周，例如 0 0 * * *（每天 0 点）
          </div>
          <div v-else class="field-hint">
            按 cron 表达式定时重新拉取该订阅并缓存结果；留空表示每次读取都是实时拉取
          </div>
        </el-form-item>
        <el-form-item v-else label="内容">
          <div class="code-editor">
            <div class="code-gutter" ref="gutterRef">
              <div
                v-for="(rows, idx) in lineWrapRows"
                :key="idx"
                class="code-line-no"
                :style="{ height: rows * lineHeightPx + 'px' }"
              >{{ idx + 1 }}</div>
            </div>
            <textarea
              ref="textareaRef"
              v-model="form.content"
              class="code-textarea"
              placeholder="本地订阅内容"
              spellcheck="false"
              @scroll="syncGutterScroll"
              @input="scheduleRecalcWraps"
            ></textarea>
          </div>
        </el-form-item>
        <el-form-item label="User-Agent">
          <el-input v-model="form.ua" placeholder="自定义 UA（可选）" />
        </el-form-item>
        <el-form-item label="操作器">
          <el-input v-model="form.processText" type="textarea" :rows="4" placeholder="每行一个操作器，例如：Sort Operator 或 Type Filter" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="previewDialog" title="选择预览客户端" width="420px" class="responsive-dialog">
      <div class="target-grid">
        <el-button
          v-for="t in targets"
          :key="t"
          class="target-btn"
          @click="openPreview(t)"
        >{{ targetLabel(t) }}</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, computed, onMounted, nextTick, onBeforeUnmount } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listSubs, createSub, patchSub, deleteSub } from '../api'
import { useTargets } from '../composables/useTargets'

const subs = ref([])
const loading = ref(false)
const saving = ref(false)
const dialog = ref(false)
const editing = ref(false)
const previewDialog = ref(false)
const previewName = ref('')
const form = ref({})
const textareaRef = ref(null)
const gutterRef = ref(null)

// Number of visual rows each logical line wraps into, e.g. [1, 3, 1] means
// line 1 takes one row, line 2 wraps across three rows, line 3 takes one row.
// Used so the gutter shows a number only at the start of each real line,
// while still letting the textarea wrap long lines normally.
const lineWrapRows = ref([1])
const lineHeightPx = ref(19.2) // must match .code-line-no line-height (12px * 1.6)

let mirrorEl = null

function getMirror() {
  if (mirrorEl) return mirrorEl
  const el = document.createElement('div')
  el.style.position = 'absolute'
  el.style.visibility = 'hidden'
  el.style.top = '0'
  el.style.left = '-99999px'
  el.style.whiteSpace = 'pre-wrap'
  el.style.wordBreak = 'break-all'
  el.style.overflowWrap = 'break-word'
  document.body.appendChild(el)
  mirrorEl = el
  return el
}

function recalcWraps() {
  const ta = textareaRef.value
  if (!ta) return
  const text = form.value.content || ''
  const lines = text.split('\n')

  const cs = window.getComputedStyle(ta)
  const mirror = getMirror()
  mirror.style.font = cs.font
  mirror.style.letterSpacing = cs.letterSpacing
  mirror.style.width = cs.width
  mirror.style.padding = cs.padding
  mirror.style.border = cs.border
  mirror.style.boxSizing = cs.boxSizing

  const lineHeight = parseFloat(cs.lineHeight) || lineHeightPx.value
  lineHeightPx.value = lineHeight

  const rows = lines.map((line) => {
    // Empty line still occupies exactly one visual row.
    mirror.textContent = line.length ? line : '\u200b'
    const h = mirror.scrollHeight
    return Math.max(1, Math.round(h / lineHeight))
  })
  lineWrapRows.value = rows.length ? rows : [1]
}

let recalcScheduled = false
function scheduleRecalcWraps() {
  if (recalcScheduled) return
  recalcScheduled = true
  requestAnimationFrame(() => {
    recalcScheduled = false
    recalcWraps()
  })
}

// Lightweight client-side check for standard 5-field cron syntax
// (minute hour day month weekday). Mirrors the backend's parser closely
// enough to give immediate feedback; the backend is the source of truth.
function isValidCron(expr) {
  const fields = expr.trim().split(/\s+/)
  if (fields.length !== 5) return false
  const bounds = [
    [0, 59],
    [0, 23],
    [1, 31],
    [1, 12],
    [0, 6],
  ]
  return fields.every((field, i) => {
    const [lo, hi] = bounds[i]
    return field.split(',').every((part) => {
      if (part === '') return false
      let base = part
      if (part.includes('/')) {
        const [b, step] = part.split('/')
        base = b
        if (!/^\d+$/.test(step) || Number(step) <= 0) return false
      }
      if (base === '*') return true
      if (base.includes('-')) {
        const [a, b] = base.split('-')
        if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) return false
        const av = Number(a)
        const bv = Number(b)
        return av >= lo && bv <= hi && av <= bv
      }
      if (!/^\d+$/.test(base)) return false
      const v = Number(base)
      return v >= lo && v <= hi
    })
  })
}

const cronValid = computed(() => isValidCron(form.value.updateCron || '*'))

function syncGutterScroll() {
  if (gutterRef.value && textareaRef.value) {
    gutterRef.value.scrollTop = textareaRef.value.scrollTop
  }
}

window.addEventListener('resize', scheduleRecalcWraps)
onBeforeUnmount(() => {
  window.removeEventListener('resize', scheduleRecalcWraps)
  if (mirrorEl && mirrorEl.parentNode) {
    mirrorEl.parentNode.removeChild(mirrorEl)
  }
})

const { targets, targetLabel, loadTargets } = useTargets()

function defaultForm() {
  return { name: '', sourceType: 'remote', url: '', updateCron: '', ua: '', content: '', processText: '' }
}

async function load() {
  loading.value = true
  try {
    const [{ data }] = await Promise.all([listSubs(), loadTargets()])
    subs.value = data
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function parseProcess(text) {
  if (!text) return []
  return text
    .split('\n')
    .map((line) => line.trim())
    .filter(Boolean)
    .map((line) => {
      const space = line.indexOf(' ')
      if (space === -1) return { type: line, args: {} }
      const type = line.slice(0, space)
      let args = {}
      try {
        args = JSON.parse(line.slice(space + 1))
      } catch {
        args = line.slice(space + 1)
      }
      return { type, args }
    })
}

function processToText(ops) {
  return (ops || [])
    .map((op) => (typeof op.args === 'object' && Object.keys(op.args || {}).length ? `${op.type} ${JSON.stringify(op.args)}` : op.type))
    .join('\n')
}

function openCreate() {
  editing.value = false
  form.value = defaultForm()
  dialog.value = true
  nextTick(recalcWraps)
}

function openEdit(row) {
  editing.value = true
  form.value = {
    name: row.name,
    sourceType: row.source === 'local' ? 'local' : 'remote',
    url: row.url || '',
    updateCron: row.updateCron || '',
    ua: row.ua || '',
    content: row.content || '',
    processText: processToText(row.process),
  }
  dialog.value = true
  nextTick(recalcWraps)
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请输入名称')
    return
  }
  if (form.value.sourceType === 'local' && !form.value.content) {
    ElMessage.warning('请输入本地订阅内容')
    return
  }
  if (form.value.sourceType === 'remote' && !form.value.url) {
    ElMessage.warning('请输入订阅链接')
    return
  }
  if (form.value.sourceType === 'remote' && form.value.updateCron && !cronValid.value) {
    ElMessage.warning('定时更新表达式格式不正确')
    return
  }
  saving.value = true
  try {
    const data = { ...form.value, process: parseProcess(form.value.processText) }
    delete data.processText
    delete data.sourceType
    data.source = form.value.sourceType
    if (form.value.sourceType === 'local') {
      data.url = ''
      data.updateCron = ''
    } else {
      data.content = ''
    }
    if (editing.value) {
      await patchSub(form.value.name, data)
    } else {
      await createSub(data)
    }
    ElMessage.success('已保存')
    dialog.value = false
    await load()
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '保存失败')
  } finally {
    saving.value = false
  }
}

async function remove(row) {
  try {
    await ElMessageBox.confirm(`确认删除订阅「${row.name}」？`, '提示', { type: 'warning' })
    await deleteSub(row.name)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.message || '删除失败')
  }
}

function preview(row) {
  previewName.value = row.name
  previewDialog.value = true
}

function openPreview(target) {
  const token = localStorage.getItem('token') || ''
  const base = location.origin + location.pathname.replace(/\/[^/]*$/, '')
  const url = `${base}/download/${encodeURIComponent(previewName.value)}?target=${encodeURIComponent(target)}&token=${encodeURIComponent(token)}&preview=1`
  window.open(url, '_blank')
  previewDialog.value = false
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
.field-hint {
  font-size: 12px;
  color: var(--text-muted);
  margin-top: 4px;
  line-height: 1.5;
}
.field-hint-error {
  color: #f56c6c;
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

.code-editor {
  display: flex;
  width: 100%;
  border: 1px solid var(--border-soft);
  border-radius: var(--radius-sm);
  overflow: hidden;
  background: var(--bg-surface);
}
.code-gutter {
  flex: 0 0 auto;
  min-width: 36px;
  padding: 8px 8px 8px 0;
  text-align: right;
  background: var(--bg-soft);
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
  user-select: none;
  overflow: hidden;
  height: 180px;
}
.code-line-no {
  overflow: hidden;
}
.code-textarea {
  flex: 1 1 auto;
  height: 180px;
  padding: 8px 10px;
  border: none;
  outline: none;
  resize: none;
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-body);
  background: transparent;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-wrap: break-word;
  overflow-y: auto;
  overflow-x: hidden;
}
</style>
