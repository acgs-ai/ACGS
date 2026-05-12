import { defineStore } from 'pinia'
import apiClient from '@/api/client'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    token: localStorage.getItem('auth_token') || null,
    isRestoring: false,
    hasRestoredSession: false
  }),

  getters: {
    isAuthenticated: (state) => !!state.token && !!state.user,
    hasToken: (state) => !!state.token,
    currentUser: (state) => state.user
  },

  actions: {
    setAuthSession(session) {
      this.token = session.access_token
      this.user = session.user
      localStorage.setItem('auth_token', this.token)
    },

    clearAuth() {
      this.token = null
      this.user = null
      this.isRestoring = false
      this.hasRestoredSession = false
      localStorage.removeItem('auth_token')
    },

    async login(username, password) {
      try {
        const response = await apiClient.post('/auth/login', {
          username,
          password
        })

        this.setAuthSession(response.data)
        this.hasRestoredSession = true

        return { success: true }
      } catch (error) {
        return {
          success: false,
          error: error.response?.data?.detail || 'Login failed'
        }
      }
    },

    logout() {
      this.clearAuth()
    },

    async fetchCurrentUser() {
      if (!this.token) return false

      try {
        const response = await apiClient.get('/auth/me')
        this.user = response.data
        this.hasRestoredSession = true
        return true
      } catch (error) {
        this.clearAuth()
        return false
      }
    },

    async restoreSession() {
      if (!this.token) {
        this.clearAuth()
        return false
      }

      if (this.hasRestoredSession && this.user) {
        return true
      }

      this.isRestoring = true
      try {
        return await this.fetchCurrentUser()
      } finally {
        this.isRestoring = false
      }
    }
  }
})
