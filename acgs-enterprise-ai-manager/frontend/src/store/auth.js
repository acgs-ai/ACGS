import { defineStore } from 'pinia'
import apiClient from '@/api/client'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    user: null,
    token: localStorage.getItem('auth_token') || null
  }),

  getters: {
    isAuthenticated: (state) => !!state.token,
    currentUser: (state) => state.user
  },

  actions: {
    async login(username, password) {
      try {
        const response = await apiClient.post('/auth/login', {
          username,
          password
        })

        this.token = response.data.access_token
        this.user = response.data.user
        localStorage.setItem('auth_token', this.token)

        return { success: true }
      } catch (error) {
        return {
          success: false,
          error: error.response?.data?.detail || 'Login failed'
        }
      }
    },

    logout() {
      this.token = null
      this.user = null
      localStorage.removeItem('auth_token')
    },

    async fetchCurrentUser() {
      if (!this.token) return

      try {
        const response = await apiClient.get('/auth/me')
        this.user = response.data
      } catch (error) {
        this.logout()
      }
    }
  }
})
