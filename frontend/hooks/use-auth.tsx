"use client"

import type React from "react"

import { useState, useEffect, createContext, useContext } from "react"
import { apiClient, type User } from "@/lib/api"
import { initTelegramWebApp, isTelegramMiniApp } from "@/lib/telegram"

interface AuthContextType {
  user: User | null
  isLoading: boolean
  isAuthenticated: boolean
  isTelegramWebApp: boolean
  isTelegramWidget: boolean
  signUp: (email: string, password: string, otpCode?: string) => Promise<void> 
  signOut: () => void
  refreshUser: () => Promise<void>
  setWebAppUser: (user: any) => void
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isTelegramWebApp, setIsTelegramWebApp] = useState(false)
  const [isTelegramWidget, setIsTelegramWidget] = useState(false)

  const refreshUser = async () => {
    try {
      const response = await apiClient.getCurrentUser()
      setUser(response.data)
    } catch (error) {
      console.error("Failed to fetch user:", error)
      setUser(null)
    }
  }

  const signUp = async (email: string, password: string, otpCode: string = "") => {
    try {
      // Передаем otp_code в apiClient
      const response = await apiClient.signUp({ email, password, otp_code: otpCode })
      setUser(response.data)
    } catch (error) {
      console.error("Sign up failed:", error)
      throw error
    }
  }

  const signOut = () => {
    setUser(null)
    setIsTelegramWidget(false)
    apiClient.setWebAppUser(null)
  }

  const setWebAppUser = async (webAppUser: any) => {
    apiClient.setWebAppUser(webAppUser)
    setIsTelegramWidget(true)
    
    // Check if user is already registered after Telegram Widget auth
    try {
      const isRegistered = await apiClient.checkUserRegistration()
      if (isRegistered) {
        await refreshUser()
      }
    } catch (error) {
      console.log("User not registered yet")
    }
  }

  useEffect(() => {
    const initAuth = async () => {
      try {
        // Ждем загрузки скрипта Telegram WebApp (максимум 2 секунды)
        let attempts = 0
        const maxAttempts = 20 // 20 попыток по 100мс = 2 секунды
        
        while (attempts < maxAttempts && typeof window !== "undefined" && !window.Telegram?.WebApp) {
          await new Promise(resolve => setTimeout(resolve, 100))
          attempts++
        }
        
        // Initialize Telegram WebApp
        const webApp = initTelegramWebApp()

        // Улучшенная проверка: используем функцию isTelegramMiniApp для более надежной проверки
        // В Telegram Mini App может быть WebApp даже без user (если пользователь не авторизован)
        const isInTelegramMiniApp = isTelegramMiniApp()

        if (isInTelegramMiniApp) {
          // User is in Telegram WebApp
          setIsTelegramWebApp(true)
          try {
            const isRegistered = await apiClient.checkUserRegistration()
            if (isRegistered) {
              await refreshUser()
            }
          } catch (error) {
            console.log("User not registered yet")
          }
        } else {
          // User is in regular browser
          setIsTelegramWebApp(false)
          
          // Check if we have webAppUser from Telegram Widget
          const webAppUser = apiClient.getWebAppUser()
          if (webAppUser) {
            setIsTelegramWidget(true)
            try {
              const isRegistered = await apiClient.checkUserRegistration()
              if (isRegistered) {
                await refreshUser()
              }
            } catch (error) {
              console.log("User not registered yet")
            }
          }
        }
      } catch (error) {
        console.error("Auth initialization error:", error)
      } finally {
        setIsLoading(false)
      }
    }

    initAuth()
  }, [])

  const value: AuthContextType = {
    user,
    isLoading,
    isAuthenticated: !!user,
    isTelegramWebApp,
    isTelegramWidget,
    signUp,
    signOut,
    refreshUser,
    setWebAppUser,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
