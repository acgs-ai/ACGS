<template>
  <div class="dashboard">
    <div class="page-header">
      <h2>Dashboard</h2>
      <p>Overview of your enterprise operations</p>
    </div>

    <div class="dashboard-grid">
      <div class="card stat-card">
        <h3>Tasks</h3>
        <div class="stat-value">{{ stats.tasks || 0 }}</div>
        <p>Active tasks</p>
      </div>

      <div class="card stat-card">
        <h3>IT Assets</h3>
        <div class="stat-value">{{ stats.assets || 0 }}</div>
        <p>Managed assets</p>
      </div>

      <div class="card stat-card">
        <h3>Projects</h3>
        <div class="stat-value">{{ stats.projects || 0 }}</div>
        <p>Active projects</p>
      </div>

      <div class="card stat-card">
        <h3>Infrastructure</h3>
        <div class="stat-value">{{ stats.infrastructure || 0 }}</div>
        <p>Infrastructure items</p>
      </div>
    </div>

    <div class="card">
      <h3>Recent Activity</h3>
      <div v-if="loading" class="loading">Loading...</div>
      <div v-else-if="activities.length === 0" class="empty-state">
        No recent activity
      </div>
      <ul v-else class="activity-list">
        <li v-for="activity in activities" :key="activity.id" class="activity-item">
          <span class="activity-type">{{ activity.type }}</span>
          <span class="activity-description">{{ activity.description }}</span>
          <span class="activity-time">{{ formatTime(activity.timestamp) }}</span>
        </li>
      </ul>
    </div>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue'
import apiClient, { totalItems } from '@/api/client'

const stats = ref({})
const activities = ref([])
const loading = ref(true)

const fetchDashboardData = async () => {
  loading.value = true
  try {
    // Fetch stats from various endpoints
    const [tasksRes, assetsRes, projectsRes, infraRes] = await Promise.allSettled([
      apiClient.get('/tasks').catch(() => ({ data: [] })),
      apiClient.get('/assets').catch(() => ({ data: [] })),
      apiClient.get('/projects').catch(() => ({ data: [] })),
      apiClient.get('/infrastructure').catch(() => ({ data: [] }))
    ])

    stats.value = {
      tasks: tasksRes.status === 'fulfilled' ? totalItems(tasksRes.value.data) : 0,
      assets: assetsRes.status === 'fulfilled' ? totalItems(assetsRes.value.data) : 0,
      projects: projectsRes.status === 'fulfilled' ? totalItems(projectsRes.value.data) : 0,
      infrastructure: infraRes.status === 'fulfilled' ? totalItems(infraRes.value.data) : 0
    }
  } catch (error) {
    console.error('Failed to fetch dashboard data:', error)
  } finally {
    loading.value = false
  }
}

const formatTime = (timestamp) => {
  return new Date(timestamp).toLocaleString()
}

onMounted(() => {
  fetchDashboardData()
})
</script>

<style scoped>
.dashboard-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
  gap: 1.5rem;
  margin-bottom: 2rem;
}

.stat-card {
  text-align: center;
}

.stat-card h3 {
  color: #7f8c8d;
  font-size: 1rem;
  margin-bottom: 1rem;
}

.stat-value {
  font-size: 3rem;
  font-weight: bold;
  color: #3498db;
  margin-bottom: 0.5rem;
}

.activity-list {
  list-style: none;
}

.activity-item {
  padding: 1rem;
  border-bottom: 1px solid #ecf0f1;
  display: flex;
  gap: 1rem;
  align-items: center;
}

.activity-item:last-child {
  border-bottom: none;
}

.activity-type {
  background: #3498db;
  color: white;
  padding: 0.25rem 0.75rem;
  border-radius: 4px;
  font-size: 0.875rem;
  font-weight: 500;
}

.activity-description {
  flex: 1;
}

.activity-time {
  color: #7f8c8d;
  font-size: 0.875rem;
}

.empty-state {
  text-align: center;
  padding: 2rem;
  color: #7f8c8d;
}
</style>
