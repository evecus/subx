<template>
  <div class="page-card">
    <div class="toolbar">
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>新建组合订阅
      </el-button>
      <el-button @click="load">
        <el-icon><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <el-table :data="cols" v-loading="loading" stripe class="desktop-table">
      <el-table-column prop="name" label="名称" min-width="140" />
      <el-table-column label="包含订阅" min-width="260">
        <template #default="{ row }">
          <el-tag v-for="s in row.subscriptions" :key="s" size="small" style="margin-right:4px">{{ s }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="300" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="mobile-cards" v-loading="loading">
      <div v-for="row in cols" :key="row.name" class="mobile-card">
        <div class="mobile-card-top">
          <span class="mobile-card-name">{{ row.name }}</span>
        </div>
        <div class="mobile-card-row" v-if="row.subscriptions && row.subscriptions.length">
          <div class="mobile-card-tags">
            <el-tag v-for="s in row.subscriptions" :key="s" size="small">{{ s }}</el-tag>
          </div>
        </div>
        <div class="mobile-card-actions">
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </div>
      </div>
      <el-empty v-if="!loading && !cols.length" description="暂无组合订阅" />
    </div>

    <el-dialog v-model="dialog" :title="editing ? '编辑组合订阅' : '新建组合订阅'" width="560px" destroy-on-close class="responsive-dialog">
      <el-form label-width="90px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="组合订阅名称" />
        </el-form-item>
        <el-form-item label="包含订阅">
          <el-select v-model="form.subscriptions" multiple filterable allow-create default-first-option style="width:100%">
            <el-option v-for="s in subs" :key="s.name" :label="s.name" :value="s.name" />
          </el-select>
        </el-form-item>
        <el-form-item label="操作器">
          <el-input v-model="form.processText" type="textarea" :rows="4" placeholder="每行一个操作器" />
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
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listSubs, listCollections, createCollection, patchCollection, deleteCollection } from '../api'
import { useTargets } from '../composables/useTargets'

const cols = ref([])
const subs = ref([])
const loading = ref(false)
const saving = ref(false)
const dialog = ref(false)
const editing = ref(false)
const previewDialog = ref(false)
const previewName = ref('')
const form = ref({ name: '', subscriptions: [], processText: '' })

const { targets, targetLabel, loadTargets } = useTargets()

function parseProcess(text) {
  if (!text) return []
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const i = line.indexOf(' ')
      if (i === -1) return { type: line, args: {} }
      const args = JSON.parse(line.slice(i + 1))
      return { type: line.slice(0, i), args }
    })
}

function processToText(ops) {
  return (ops || [])
    .map((op) => (typeof op.args === 'object' && Object.keys(op.args || {}).length ? `${op.type} ${JSON.stringify(op.args)}` : op.type))
    .join('\n')
}

async function load() {
  loading.value = true
  try {
    const [c, s] = await Promise.all([listCollections(), listSubs(), loadTargets()])
    cols.value = c.data
    subs.value = s.data
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = false
  form.value = { name: '', subscriptions: [], processText: '' }
  dialog.value = true
}

function openEdit(row) {
  editing.value = true
  form.value = {
    name: row.name,
    subscriptions: row.subscriptions || [],
    processText: processToText(row.process),
  }
  dialog.value = true
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请输入名称')
    return
  }
  saving.value = true
  try {
    const data = { ...form.value, process: parseProcess(form.value.processText) }
    delete data.processText
    if (editing.value) {
      await patchCollection(form.value.name, data)
    } else {
      await createCollection(data)
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
    await ElMessageBox.confirm(`确认删除组合订阅「${row.name}」？`, '提示', { type: 'warning' })
    await deleteCollection(row.name)
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
.mobile-card-row { padding: 3px 0; }
.mobile-card-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
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
