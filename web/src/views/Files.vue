<template>
  <div class="page-card">
    <div class="toolbar">
      <el-button type="primary" @click="openCreate">
        <el-icon><Plus /></el-icon>新建
      </el-button>
      <el-button @click="load">
        <el-icon><Refresh /></el-icon>刷新
      </el-button>
    </div>

    <el-table :data="files" v-loading="loading" stripe class="desktop-table">
      <el-table-column prop="name" label="名称" min-width="160" />
      <el-table-column label="内容预览" min-width="260">
        <template #default="{ row }">
          <span class="content-snippet">{{ snippet(row.content) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="260" fixed="right">
        <template #default="{ row }">
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </template>
      </el-table-column>
    </el-table>

    <div class="mobile-cards" v-loading="loading">
      <div v-for="row in files" :key="row.name" class="mobile-card">
        <div class="mobile-card-top">
          <span class="mobile-card-name">{{ row.name }}</span>
        </div>
        <div class="mobile-card-row" v-if="row.content">
          <span class="mobile-card-value ellipsis">{{ snippet(row.content) }}</span>
        </div>
        <div class="mobile-card-actions">
          <el-button size="small" @click="preview(row)">预览</el-button>
          <el-button size="small" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" type="danger" @click="remove(row)">删除</el-button>
        </div>
      </div>
      <el-empty v-if="!loading && !files.length" description="暂无文件" />
    </div>

    <el-dialog v-model="dialog" :title="editing ? '编辑文件' : '新建文件'" width="640px" destroy-on-close class="responsive-dialog">
      <el-form label-width="90px">
        <el-form-item label="名称" required>
          <el-input v-model="form.name" placeholder="文件名，例如 rules.txt" />
        </el-form-item>
        <el-form-item label="内容">
          <el-input v-model="form.content" type="textarea" :rows="12" placeholder="文件文本内容" class="content-textarea" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialog = false">取消</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listFiles, createFile, patchFile, deleteFile, getFileRawUrl } from '../api'

const files = ref([])
const loading = ref(false)
const saving = ref(false)
const dialog = ref(false)
const editing = ref(false)
const form = ref({ name: '', content: '' })

function snippet(content) {
  if (!content) return ''
  const line = content.split('\n')[0] || ''
  return line.length > 80 ? line.slice(0, 80) + '…' : line
}

async function load() {
  loading.value = true
  try {
    const { data } = await listFiles()
    files.value = data
  } catch (e) {
    ElMessage.error(e.response?.data?.message || '加载失败')
  } finally {
    loading.value = false
  }
}

function openCreate() {
  editing.value = false
  form.value = { name: '', content: '' }
  dialog.value = true
}

function openEdit(row) {
  editing.value = true
  form.value = { name: row.name, content: row.content || '' }
  dialog.value = true
}

async function save() {
  if (!form.value.name) {
    ElMessage.warning('请输入文件名')
    return
  }
  saving.value = true
  try {
    if (editing.value) {
      await patchFile(form.value.name, form.value)
    } else {
      await createFile(form.value)
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
    await ElMessageBox.confirm(`确认删除文件「${row.name}」？`, '提示', { type: 'warning' })
    await deleteFile(row.name)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error(e.response?.data?.message || '删除失败')
  }
}

function preview(row) {
  window.open(getFileRawUrl(row.name), '_blank')
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
.content-snippet {
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
}
.content-textarea :deep(textarea) {
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
  line-height: 1.6;
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
.mobile-card-value.ellipsis {
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: block;
  min-width: 0;
  color: var(--text-muted);
  font-family: ui-monospace, SFMono-Regular, Consolas, Menlo, monospace;
  font-size: 12px;
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
}
</style>
