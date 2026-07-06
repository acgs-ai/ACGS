<template>
  <div class="assets-view">
    <div class="page-header">
      <h2>IT Assets Management</h2>
      <button @click="showCreateForm = true" class="btn btn-primary">Add Asset</button>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="showCreateForm" class="card">
      <h3>{{ editingAsset ? 'Edit Asset' : 'Add New Asset' }}</h3>
      <form @submit.prevent="saveAsset">
        <div class="form-group">
          <label>Asset Name</label>
          <input v-model="form.name" type="text" required />
        </div>
        <div class="form-group">
          <label>Type</label>
          <select v-model="form.type">
            <option value="server">Server</option>
            <option value="workstation">Workstation</option>
            <option value="laptop">Laptop</option>
            <option value="network_device">Network Device</option>
            <option value="storage">Storage</option>
            <option value="software_license">Software License</option>
            <option value="other">Other</option>
          </select>
        </div>
        <div class="form-group">
          <label>Status</label>
          <select v-model="form.status">
            <option value="active">Active</option>
            <option value="maintenance">Maintenance</option>
            <option value="retired">Retired</option>
          </select>
        </div>
        <div class="form-group">
          <label>Location</label>
          <input v-model="form.location" type="text" />
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-success">Save</button>
          <button type="button" @click="cancelForm" class="btn">Cancel</button>
        </div>
      </form>
    </div>

    <div v-if="loading" class="loading">Loading assets...</div>

    <table v-else-if="assets.length > 0" class="table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Type</th>
          <th>Status</th>
          <th>Location</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="asset in assets" :key="asset.id">
          <td>{{ asset.name }}</td>
          <td>{{ asset.type }}</td>
          <td><span :class="'badge badge-' + asset.status">{{ asset.status }}</span></td>
          <td>{{ asset.location }}</td>
          <td>
            <button @click="editAsset(asset)" class="btn btn-sm">Edit</button>
            <button @click="deleteAsset(asset.id)" class="btn btn-sm btn-danger">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-else class="card">
      <p class="empty-state">No assets found. Add your first asset!</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import apiClient, { listItems } from '@/api/client'

const assets = ref([])
const loading = ref(false)
const error = ref('')
const showCreateForm = ref(false)
const editingAsset = ref(null)
const form = ref({
  name: '',
  type: 'server',
  status: 'active',
  location: ''
})

const fetchAssets = async () => {
  loading.value = true
  error.value = ''
  try {
    const response = await apiClient.get('/assets')
    assets.value = listItems(response.data)
  } catch (err) {
    error.value = 'Failed to load assets'
    console.error(err)
  } finally {
    loading.value = false
  }
}

const saveAsset = async () => {
  try {
    if (editingAsset.value) {
      await apiClient.put(`/assets/${editingAsset.value.id}`, form.value)
    } else {
      await apiClient.post('/assets', form.value)
    }
    await fetchAssets()
    cancelForm()
  } catch (err) {
    error.value = 'Failed to save asset'
    console.error(err)
  }
}

const editAsset = (asset) => {
  editingAsset.value = asset
  form.value = { ...asset }
  showCreateForm.value = true
}

const deleteAsset = async (id) => {
  if (!confirm('Are you sure you want to delete this asset?')) return

  try {
    await apiClient.delete(`/assets/${id}`)
    await fetchAssets()
  } catch (err) {
    error.value = 'Failed to delete asset'
    console.error(err)
  }
}

const cancelForm = () => {
  showCreateForm.value = false
  editingAsset.value = null
  form.value = {
    name: '',
    type: 'server',
    status: 'active',
    location: ''
  }
}

onMounted(() => {
  fetchAssets()
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

.badge-active { background: #2ecc71; color: white; }
.badge-maintenance { background: #f39c12; color: white; }
.badge-retired { background: #95a5a6; color: white; }
</style>
