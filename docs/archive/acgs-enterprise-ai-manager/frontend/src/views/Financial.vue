<template>
  <div class="financial-view">
    <div class="page-header">
      <h2>Financial Management</h2>
      <button @click="showCreateForm = true" class="btn btn-primary">Add Transaction</button>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="showCreateForm" class="card">
      <h3>{{ editingItem ? 'Edit Transaction' : 'Add New Transaction' }}</h3>
      <form @submit.prevent="saveItem">
        <div class="form-group">
          <label>Description</label>
          <input v-model="form.description" type="text" required />
        </div>
        <div class="form-group">
          <label>Amount</label>
          <input v-model="form.amount" type="number" step="0.01" required />
        </div>
        <div class="form-group">
          <label>Type</label>
          <select v-model="form.type">
            <option value="expense">Expense</option>
            <option value="revenue">Revenue</option>
            <option value="budget_allocation">Budget Allocation</option>
            <option value="invoice">Invoice</option>
            <option value="payment">Payment</option>
          </select>
        </div>
        <div class="form-group">
          <label>Category</label>
          <input v-model="form.category" type="text" required />
        </div>
        <div class="form-group">
          <label>Date</label>
          <input v-model="form.date" type="date" required />
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-success">Save</button>
          <button type="button" @click="cancelForm" class="btn">Cancel</button>
        </div>
      </form>
    </div>

    <div v-if="loading" class="loading">Loading financial data...</div>

    <table v-else-if="items.length > 0" class="table">
      <thead>
        <tr>
          <th>Description</th>
          <th>Amount</th>
          <th>Type</th>
          <th>Category</th>
          <th>Date</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="item in items" :key="item.id">
          <td>{{ item.description }}</td>
          <td :class="item.type === 'revenue' ? 'text-success' : 'text-danger'">
            {{ item.type === 'revenue' ? '+' : '-' }}${{ item.amount }}
          </td>
          <td><span :class="'badge badge-' + item.type">{{ item.type }}</span></td>
          <td>{{ item.category }}</td>
          <td>{{ formatDate(item.date || item.created_at) }}</td>
          <td>
            <button @click="editItem(item)" class="btn btn-sm">Edit</button>
            <button @click="deleteItem(item.id)" class="btn btn-sm btn-danger">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-else class="card">
      <p class="empty-state">No financial records found.</p>
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
const today = () => new Date().toISOString().slice(0, 10)
const form = ref({ description: '', amount: 0, type: 'expense', category: '', date: today() })

const fetchItems = async () => {
  loading.value = true
  error.value = ''
  try {
    const response = await apiClient.get('/financial')
    items.value = listItems(response.data)
  } catch (err) {
    error.value = 'Failed to load financial data'
    console.error(err)
  } finally {
    loading.value = false
  }
}

const saveItem = async () => {
  try {
    if (editingItem.value) {
      await apiClient.put(`/financial/${editingItem.value.id}`, form.value)
    } else {
      await apiClient.post('/financial', form.value)
    }
    await fetchItems()
    cancelForm()
  } catch (err) {
    error.value = 'Failed to save transaction'
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
    await apiClient.delete(`/financial/${id}`)
    await fetchItems()
  } catch (err) {
    error.value = 'Failed to delete transaction'
    console.error(err)
  }
}

const cancelForm = () => {
  showCreateForm.value = false
  editingItem.value = null
  form.value = { description: '', amount: 0, type: 'expense', category: '', date: today() }
}

const formatDate = (date) => {
  return new Date(date).toLocaleDateString()
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

.badge-revenue { background: #2ecc71; color: white; }
.badge-expense { background: #e74c3c; color: white; }
.badge-budget_allocation { background: #3498db; color: white; }
.badge-invoice { background: #9b59b6; color: white; }
.badge-payment { background: #f39c12; color: white; }

.text-success { color: #2ecc71; font-weight: 600; }
.text-danger { color: #e74c3c; font-weight: 600; }
</style>
