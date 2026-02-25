"use client"

import type React from "react"

import { useAuth } from "@/hooks/use-auth"
import { useAdmin } from "@/hooks/use-admin"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { SignUpForm } from "@/components/auth/sign-up-form"
import { TelegramWidget, TelegramAuthError } from "@/components/auth/telegram-widget"
import { BottomNavigation } from "./layout/bottom-navigation"
import { MaintenancePage } from "./maintenance-page"

interface RouteGuardProps {
  children: React.ReactNode
}

export function RouteGuard({ children }: RouteGuardProps) {
  const { 
    user, 
    isLoading, 
    isAuthenticated, 
    isTelegramWebApp, 
    isTelegramWidget, 
    setWebAppUser 
  } = useAuth()
  const { isAdmin } = useAdmin()

  const handleTelegramAuth = async (telegramUser: any) => {
    try {
      await setWebAppUser(telegramUser)
    } catch (error) {
      console.error("Failed to set web app user:", error)
    }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background relative z-10">
        <div className="flex items-center justify-center min-h-[calc(100vh-3.5rem)]">
          <LoadingSpinner />
        </div>
      </div>
    )
  }

  if (isAuthenticated) {
    // if (!isAdmin) {
    //   return <MaintenancePage />
    // }

    return <>
      <div className="pb-16 pb-safe relative z-10">
        {children}
      </div>

      <BottomNavigation/>
    </>
  }

  // If user is in Telegram WebApp but not registered, show sign up form
  if (isTelegramWebApp) {
    return (
      <div className="min-h-screen bg-background relative z-10">
        <SignUpForm />
      </div>
    )
  }

  // If user is in regular browser and not authenticated via Telegram Widget
  if (!isTelegramWidget) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center p-4 relative z-10">
        <div className="w-full max-w-md">
          <TelegramWidget 
            onAuth={handleTelegramAuth} 
            botName={process.env.TELEGRAM_BOT_NAME || "your_bot_name"}
          />
        </div>
      </div>
    )
  }

  // If user is authenticated via Telegram Widget but not registered, show sign up form
  return (
    <div className="min-h-screen bg-background relative z-10">
      <SignUpForm />
    </div>
  )
}
