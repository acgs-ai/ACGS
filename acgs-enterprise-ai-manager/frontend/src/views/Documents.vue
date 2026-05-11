<template>
  <div class="documents-view">
    <div class="page-header">
      <h2>Documents Management</h2>
      <button @click="showCreateForm = true" class="btn btn-primary">Add Document</button>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="showCreateForm" class="card">
      <h3>{{ editingDoc ? 'Edit Document' : 'Add New Document' }}</h3>
      <form @submit.prevent="saveDocument">
        <div class="form-group">
          <label>Title</label>
          <input v-model="form.title" type="text" required />
        </div>
        <div class="form-group">
          <label>Content</label>
          <textarea v-model="form.content"></textarea>
        </div>
        <div class="form-group">
          <label>Type</label>
          <select v-model="form.type">
            <option value="specification">Specification</option>
            <option value="policy">Policy</option>
            <option value="procedure">Procedure</option>
            <option value="report">Report</option>
            <option value="contract">Contract</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="form-group">
          <label>URL/Path</label>
          <input v-model="form.file_path" type="text" />
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-success">Save</button>
          <button type="button" @click="cancelForm" class="btn">Cancel</button>
        </div>
      </form>
    </div>

    <div v-if="loading" class="loading">Loading documents...</div>

    <table v-else-if="documents.length > 0" class="table">
      <thead>
        <tr>
          <th>Title</th>
          <th>Type</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="doc in documents" :key="doc.id">
          <td>{{ doc.title }}</td>
          <td><span :class="'badge badge-' + doc.type">{{ doc.type }}</span></td>
          <td>{{ formatDate(doc.created_date || doc.created_at) }}</td>
          <td>
            <button @click="editDocument(doc)" class="btn btn-sm">Edit</button>
            <button @click="deleteDocument(doc.id)" class="btn btn-sm btn-danger">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-else class="card">
      <p class="empty-state">No documents found.</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import apiClient, { listItems } from '@/api/client'

const documents = ref([])
const loading = ref(false)
const error = ref('')
const showCreateForm = ref(false)
const editingDoc = ref(null)
const form = ref({ title: '', content: '', type: 'policy', file_path: '' })

const fetchDocuments = async () => {
  loading.value = true
  error.value = ''
  try {
    const response = await apiClient.get('/documents')
    documents.value = listItems(response.data)
  } catch (err) {
    error.value = 'Failed to load documents'
    console.error(err)
  } finally {
    loading.value = false
  }
}

const saveDocument = async () => {
  try {
    if (editingDoc.value) {
      await apiClient.put(`/documents/${editingDoc.value.id}`, form.value)
    } else {
      await apiClient.post('/documents', form.value)
    }
    await fetchDocuments()
    cancelForm()
  } catch (err) {
    error.value = 'Failed to save document'
    console.error(err)
  }
}

const editDocument = (doc) => {
  editingDoc.value = doc
  form.value = { ...doc }
  showCreateForm.value = true
}

const deleteDocument = async (id) => {
  if (!confirm('Are you sure?')) return
  try {
    await apiClient.delete(`/documents/${id}`)
    await fetchDocuments()
  } catch (err) {
    error.value = 'Failed to delete document'
    console.error(err)
  }
}

const cancelForm = () => {
  showCreateForm.value = false
  editingDoc.value = null
  form.value = { title: '', content: '', type: 'policy', file_path: '' }
}

const formatDate = (date) => {
  return new Date(date).toLocaleDateString()
}

onMounted(() => {
  fetchDocuments()
})
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 2rem;
}

.form-actions {
  display: flex;
  gap: 1rem;
  margin-top: 1rem;
}

.btn-sm {
  padding: 0.5rem 1rem;
  font-size: 0.875rem;
  margin-right: 0.5rem;
}

.badge {
  padding: 0.25rem 0.75rem;
  border-radius: 12px;
  font-size: 0.875rem;
  font-weight: 500;
}

.badge-policy { background: #3498db; color: white; }
.badge-procedure { background: #9b59b6; color: white; }
.badge-report { background: #2ecc71; color: white; }
.badge-contract { background: #e67e22; color: white; }
</style>
