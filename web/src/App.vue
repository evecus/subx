<template>
  <router-view />
</template>

<script setup>
</script>

<style>
:root {
  --bg-page: #f7f8fc;
  --bg-surface: #ffffff;
  --bg-soft: #f2f3fb;
  --brand-1: #6366f1;
  --brand-2: #8b5cf6;
  --brand-3: #06b6d4;
  --brand-gradient: linear-gradient(120deg, #6366f1 0%, #8b5cf6 55%, #a855f7 100%);
  --text-strong: #1e1b2e;
  --text-body: #4b4a63;
  --text-muted: #9694ab;
  --border-soft: #ebeaf4;
  --shadow-sm: 0 1px 2px rgba(76, 60, 150, 0.06);
  --shadow-md: 0 8px 24px rgba(99, 102, 241, 0.10);
  --shadow-lg: 0 16px 40px rgba(99, 102, 241, 0.16);
  --radius-sm: 8px;
  --radius-md: 14px;
  --radius-lg: 20px;
}

* { margin: 0; padding: 0; box-sizing: border-box; }
html, body, #app { height: 100%; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'PingFang SC', 'Microsoft YaHei', Helvetica, Arial, sans-serif;
  background: var(--bg-page);
  color: var(--text-body);
  -webkit-font-smoothing: antialiased;
}

/* ---- Element Plus global re-skin: white / lively ---- */
.el-button {
  border-radius: var(--radius-sm) !important;
  font-weight: 500;
  transition: transform 0.18s ease, box-shadow 0.18s ease, opacity 0.18s ease;
}
.el-button:not(.is-text):not(.is-link):hover {
  transform: translateY(-1px);
}
.el-button--primary {
  background: var(--brand-gradient) !important;
  border: none !important;
  box-shadow: var(--shadow-md);
}
.el-button--primary:hover {
  box-shadow: var(--shadow-lg);
  opacity: 0.95;
}
.el-button--danger {
  background: linear-gradient(120deg, #fb7185, #f43f5e) !important;
  border: none !important;
}

.el-card {
  border: 1px solid var(--border-soft) !important;
  border-radius: var(--radius-lg) !important;
  box-shadow: var(--shadow-sm) !important;
  background: var(--bg-surface) !important;
}

.el-table {
  --el-table-border-color: var(--border-soft);
  --el-table-header-bg-color: var(--bg-soft);
  --el-table-row-hover-bg-color: #f1f0fd;
  border-radius: var(--radius-md);
  overflow: hidden;
}
.el-table th.el-table__cell {
  color: var(--text-strong);
  font-weight: 600;
}
.el-table__row {
  transition: background-color 0.15s ease;
}

.el-dialog {
  border-radius: var(--radius-lg) !important;
  overflow: hidden;
  box-shadow: var(--shadow-lg) !important;
}
.el-dialog__header {
  padding-bottom: 16px !important;
}
.el-dialog__title {
  font-weight: 700;
  color: var(--text-strong);
}

.el-input__wrapper, .el-textarea__inner {
  border-radius: var(--radius-sm) !important;
  box-shadow: 0 0 0 1px var(--border-soft) inset !important;
  transition: box-shadow 0.15s ease;
}
.el-input__wrapper.is-focus, .el-textarea__inner:focus {
  box-shadow: 0 0 0 1px var(--brand-1) inset, 0 0 0 3px rgba(99,102,241,0.12) !important;
}

.el-tag {
  border-radius: 999px !important;
  border: none !important;
  font-weight: 500;
  background: var(--bg-soft) !important;
  color: var(--brand-1) !important;
}

.el-radio-button__inner {
  border-radius: var(--radius-sm) !important;
}
.el-radio-button:first-child .el-radio-button__inner {
  border-radius: var(--radius-sm) 0 0 var(--radius-sm) !important;
}
.el-radio-button:last-child .el-radio-button__inner {
  border-radius: 0 var(--radius-sm) var(--radius-sm) 0 !important;
}
.el-radio-button__original-radio:checked + .el-radio-button__inner {
  background: var(--brand-gradient) !important;
  border-color: transparent !important;
  box-shadow: none !important;
}

.el-alert {
  border-radius: var(--radius-sm) !important;
}

.el-menu {
  background: transparent !important;
}

/* ---- Responsive dialogs on small screens ---- */
@media (max-width: 768px) {
  .el-overlay-dialog {
    padding: 0 !important;
  }
  .el-dialog {
    width: 100% !important;
    max-width: 100vw !important;
    margin: 0 !important;
    border-radius: 0 !important;
    height: 100dvh;
    max-height: 100dvh;
    display: flex;
    flex-direction: column;
  }
  .el-dialog__header {
    padding: 16px !important;
    flex-shrink: 0;
  }
  .el-dialog__body {
    flex: 1 1 auto;
    overflow-y: auto;
    padding: 0 16px !important;
  }
  .el-dialog__footer {
    flex-shrink: 0;
    padding: 12px 16px !important;
    padding-bottom: max(12px, env(safe-area-inset-bottom)) !important;
  }
  .el-form-item__label {
    float: none !important;
    display: block !important;
    text-align: left !important;
    width: auto !important;
  }
  .el-form-item__content {
    margin-left: 0 !important;
  }
  .el-message-box {
    width: calc(100vw - 32px) !important;
  }
}
</style>
