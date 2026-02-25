"use client"

import { useEffect, useRef, useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"

interface TelegramWidgetProps {
  onAuth: (user: any) => void
  botName: string
}

export function TelegramWidget({ onAuth, botName }: TelegramWidgetProps) {
  const widgetRef = useRef<HTMLDivElement>(null)
  const [hasError, setHasError] = useState(false)

  useEffect(() => {
    // Check if script is already loaded
    const existingScript = document.querySelector('script[src*="telegram-widget.js"]')
    if (existingScript) {
      // Если скрипт уже загружен, не показываем ошибку, а используем существующий
      console.log("Telegram Widget script already loaded")
      return
    }

    // Load Telegram Login Widget script
    const script = document.createElement("script")
    script.src = "https://telegram.org/js/telegram-widget.js?22"
    script.setAttribute("data-telegram-login", botName)
    script.setAttribute("data-size", "large")
    script.setAttribute("data-onauth", "onTelegramAuth(user)")
    script.setAttribute("data-request-access", "write")
    script.async = true

    // Handle script loading errors
    script.onerror = () => {
      console.error("Failed to load Telegram Widget script")
      setHasError(true)
    }

    // Define global callback function
    ;(window as any).onTelegramAuth = (user: any) => {
      console.log("Telegram auth successful:", user)
      onAuth(user)
    }

    if (widgetRef.current) {
      widgetRef.current.appendChild(script)
    }

    return () => {
      // Cleanup
      if (script.parentNode) {
        script.parentNode.removeChild(script)
      }
      delete (window as any).onTelegramAuth
    }
  }, [botName, onAuth])

  if (hasError) {
    return <TelegramAuthError />
  }

  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="text-center">
        <CardTitle>Авторизация через Telegram</CardTitle>
        <CardDescription>
          Войдите в систему используя свой аккаунт Telegram
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div ref={widgetRef} className="flex justify-center" />
      </CardContent>
    </Card>
  )
}

// Error component for when Telegram Widget is not available
export function TelegramAuthError() {
  return (
    <Card className="w-full max-w-md mx-auto">
      <CardHeader className="text-center">
        <CardTitle>Ошибка авторизации</CardTitle>
        <CardDescription>
          Не удалось загрузить Telegram Login Widget
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="text-center text-sm text-muted-foreground">
          Пожалуйста, обновите страницу или попробуйте позже
        </div>
      </CardContent>
    </Card>
  )
}
