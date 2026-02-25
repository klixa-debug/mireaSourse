"use client"

import type React from "react"

import { Button } from "@/components/ui/button"
import { ThemeToggle } from "@/components/theme-toggle"
import { useAuth } from "@/hooks/use-auth"
import { Bell, GraduationCap, ArrowLeft } from "lucide-react"

interface AppHeaderProps {
  title: string
  showBackButton?: boolean
  onBack?: () => void
  actions?: React.ReactNode
}

export function AppHeader({ title, showBackButton, onBack, actions }: AppHeaderProps) {
  const { user } = useAuth()

  return (
    <header className="sticky top-0 z-50 w-full border-b bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60">
      <div className="container flex h-14 items-center justify-between px-4">
        <div className="flex items-center space-x-2">
          {showBackButton && (
            <Button variant="ghost" size="icon" onClick={onBack}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
          )}
          <GraduationCap className="h-6 w-6 text-primary" />
          <h1 className="text-lg font-semibold">{title}</h1>
        </div>
        <div className="flex items-center space-x-2">
          {actions}
          {user && (
            <Button variant="ghost" size="icon">
              <Bell className="h-4 w-4" />
            </Button>
          )}
          <ThemeToggle />
        </div>
      </div>
    </header>
  )
}
