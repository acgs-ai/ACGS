<template>
  <div class="infrastructure-view">
    <div class="page-header">
      <h2>Infrastructure Management</h2>
      <button @click="showCreateForm = true" class="btn btn-primary">Add Infrastructure</button>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="showCreateForm" class="card">
      <h3>{{ editingItem ? 'Edit Infrastructure' : 'Add New Infrastructure' }}</h3>
      <form @submit.prevent="saveItem">
        <div class="form-group">
          <label>Name</label>
          <input v-model="form.name" type="text" required />
        </div>
        <div class="form-group">
          <label>Type</label>
          <select v-model="form.type">
            <option value="compute">Compute</option>
            <option value="network">Network</option>
            <option value="storage">Storage</option>
            <option value="database">Database</option>
            <option value="security">Security</option>
            <option value="monitoring">Monitoring</option>
          </select>
        </div>
        <div class="form-group">
          <label>Status</label>
          <select v-model="form.status">
            <option value="operational">Operational</option>
            <option value="degraded">Degraded</option>
            <option value="down">Down</option>
          </select>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-success">Save</button>
          <button type="button" @click="cancelForm" class="btn">Cancel</button>
        </div>
      </form>
    </div>

    <div v-if="loading" class="loading">Loading infrastructure...</div>

    <table v-else-if="items.length > 0" class="table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in items" :key="item.id">
          <td>{{ item.name }}</td>
          <td>{{ item.type }}</td>
          <td><span :class="'badge badge-' + item.status">{{ item.status }}</span></td>
          <td>
            <button @click="editItem(item)" class="btn btn-sm">Edit</button>
            <button @click="deleteItem(item.id)" class="btn btn-sm btn-danger">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-else class="card">
      <p class="empty-state">No infrastructure items found.</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import apiClient, { listItems } from '@/api/client'

const items = ref([])
const loading = ref(false)
const error = ref('')
const showCreateForm = ref(false)
const editingItem = ref(null)
const form = ref({ name: '', type: 'compute', status: 'operational' })

const fetchItems = async () => {
  loading.value = true
  error.value = ''
  try {
    const response = await apiClient.get('/infrastructure')
    items.value = listItems(response.data)
  } catch (err) {
    error.value = 'Failed to load infrastructure'
    console.error(err)
  } finally {
    loading.value = false
  }
}

const saveItem = async () => {
  try {
    if (editingItem.value) {
      await apiClient.put(`/infrastructure/${editingItem.value.id}`, form.value)
    } else {
      await apiClient.post('/infrastructure', form.value)
    }
    await fetchItems()
    cancelForm()
  } catch (err) {
    error.value = 'Failed to save infrastructure'
    console.error(err)
  }
}

const editItem = (item) => {
  editingItem.value = item
  form.value = { ...item }
  showCreateForm.value = true
}

const deleteItem = async (id) => {
  if (!confirm('Are you sure?')) return
  try {
    await apiClient.delete(`/infrastructure/${id}`)
    await fetchItems()
  } catch (err) {
    error.value = 'Failed to delete infrastructure'
    console.error(err)
  }
}

const cancelForm = () => {
  showCreateForm.value = false
  editingItem.value = null
  form.value = { name: '', type: 'compute', status: 'operational' }
}

onMounted(() => {
  fetchItems()
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

.badge-operational { background: #2ecc71; color: white; }
.badge-degraded { background: #f39c12; color: white; }
.badge-down { background: #e74c3c; color: white; }
</style>
