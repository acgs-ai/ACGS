<template>
  <div class="tasks-view">
    <div class="page-header">
      <h2>Tasks Management</h2>
      <button @click="showCreateForm = true" class="btn btn-primary">Create Task</button>
    </div>

    <div v-if="error" class="error">{{ error }}</div>

    <div v-if="showCreateForm" class="card">
      <h3>{{ editingTask ? 'Edit Task' : 'Create New Task' }}</h3>
      <form @submit.prevent="saveTask">
        <div class="form-group">
          <label>Title</label>
          <input v-model="form.title" type="text" required />
        </div>
        <div class="form-group">
          <label>Description</label>
          <textarea v-model="form.description"></textarea>
        </div>
        <div class="form-group">
          <label>Status</label>
          <select v-model="form.status">
            <option value="todo">To Do</option>
            <option value="in_progress">In Progress</option>
            <option value="blocked">Blocked</option>
            <option value="review">Review</option>
            <option value="done">Done</option>
            <option value="cancelled">Cancelled</option>
          </select>
        </div>
        <div class="form-group">
          <label>Priority</label>
          <select v-model="form.priority">
            <option value="low">Low</option>
            <option value="medium">Medium</option>
            <option value="high">High</option>
          </select>
        </div>
        <div class="form-actions">
          <button type="submit" class="btn btn-success">Save</button>
          <button type="button" @click="cancelForm" class="btn">Cancel</button>
        </div>
      </form>
    </div>

    <div v-if="loading" class="loading">Loading tasks...</div>

    <table v-else-if="tasks.length > 0" class="table">
      <thead>
        <tr>
          <th>Title</th>
          <th>Status</th>
          <th>Priority</th>
          <th>Created</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="task in tasks" :key="task.id">
          <td>{{ task.title }}</td>
          <td><span :class="'badge badge-' + task.status">{{ task.status }}</span></td>
          <td><span :class="'badge badge-' + task.priority">{{ task.priority }}</span></td>
          <td>{{ formatDate(task.created_at) }}</td>
          <td>
            <button @click="editTask(task)" class="btn btn-sm">Edit</button>
            <button @click="deleteTask(task.id)" class="btn btn-sm btn-danger">Delete</button>
          </td>
        </tr>
      </tbody>
    </table>

    <div v-else class="card">
      <p class="empty-state">No tasks found. Create your first task!</p>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import apiClient, { listItems } from '@/api/client'

const tasks = ref([])
const loading = ref(false)
const error = ref('')
const showCreateForm = ref(false)
const editingTask = ref(null)
const form = ref({
  title: '',
  description: '',
  status: 'todo',
  priority: 'medium'
})

const fetchTasks = async () => {
  loading.value = true
  error.value = ''
  try {
    const response = await apiClient.get('/tasks')
    tasks.value = listItems(response.data)
  } catch (err) {
    error.value = 'Failed to load tasks'
    console.error(err)
  } finally {
    loading.value = false
  }
}

const saveTask = async () => {
  try {
    if (editingTask.value) {
      await apiClient.put(`/tasks/${editingTask.value.id}`, form.value)
    } else {
      await apiClient.post('/tasks', form.value)
    }
    await fetchTasks()
    cancelForm()
  } catch (err) {
    error.value = 'Failed to save task'
    console.error(err)
  }
}

const editTask = (task) => {
  editingTask.value = task
  form.value = { ...task }
  showCreateForm.value = true
}

const deleteTask = async (id) => {
  if (!confirm('Are you sure you want to delete this task?')) return

  try {
    await apiClient.delete(`/tasks/${id}`)
    await fetchTasks()
  } catch (err) {
    error.value = 'Failed to delete task'
    console.error(err)
  }
}

const cancelForm = () => {
  showCreateForm.value = false
  editingTask.value = null
  form.value = {
    title: '',
    description: '',
    status: 'todo',
    priority: 'medium'
  }
}

const formatDate = (date) => {
  return new Date(date).toLocaleDateString()
}

onMounted(() => {
  fetchTasks()
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

.badge-todo { background: #95a5a6; color: white; }
.badge-in_progress { background: #3498db; color: white; }
.badge-blocked { background: #e67e22; color: white; }
.badge-review { background: #9b59b6; color: white; }
.badge-done { background: #2ecc71; color: white; }
.badge-cancelled { background: #7f8c8d; color: white; }
.badge-low { background: #95a5a6; color: white; }
.badge-medium { background: #f39c12; color: white; }
.badge-high { background: #e74c3c; color: white; }
</style>
