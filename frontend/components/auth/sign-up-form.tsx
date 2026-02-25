"use client"

import type React from "react"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { useAuth } from "@/hooks/use-auth"
import { GraduationCap, Loader2, Mail, ArrowLeft } from "lucide-react"
import { TotpSetup } from "./totp-setup"

export function SignUpForm() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [otpCode, setOtpCode] = useState("") // Состояние для кода из почты
  const [isOtpStep, setIsOtpStep] = useState(false) // Флаг: находимся ли мы на шаге ввода кода
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [showTotpSetup, setShowTotpSetup] = useState(false)
  
  // Обновите useAuth, чтобы signUp принимал третий параметр - otpCode
  const { signUp, refreshUser } = useAuth()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")

    try {
      // Отправляем данные на бэкенд. При первом шаге otpCode будет пустой строкой.
      await signUp(email, password, otpCode)
      // Если ошибок нет, значит авторизация успешна (сразу или после ввода кода)
      await refreshUser()
    } catch (error: any) {
      const errorMessage = error?.message || error?.toString() || ""

      // 1. Старая проверка на TOTP-приложение (Google Authenticator)
      if (errorMessage.includes("totp_secret_required") || errorMessage.includes("Требуется двухфакторная авторизация")) {
        setShowTotpSetup(true)
      } 
      // 2. НОВАЯ ПРОВЕРКА: Код на почту (Бэкенд должен вернуть ошибку с ключом email_otp_required)
      else if (errorMessage.includes("email_otp_required") || errorMessage.includes("код на почту")) {
        setIsOtpStep(true)
        if (otpCode !== "") {
          setError("Неверный код или срок его действия истек. Попробуйте снова.")
        }
      } 
      // 3. Другие ошибки (неверный пароль и т.д.)
      else {
        setError("Ошибка регистрации. " + errorMessage)
      }
    } finally {
      setIsLoading(false)
    }
  }

  const handleTotpComplete = async () => {
    await refreshUser()
    setShowTotpSetup(false)
  }

  if (showTotpSetup) {
    return <TotpSetup onComplete={handleTotpComplete} onBack={() => setShowTotpSetup(false)} />
  }

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4">
      <Card className="w-full max-w-md mx-auto">
        <CardHeader className="text-center">
          <div className="flex justify-center mb-4">
            <GraduationCap className="h-12 w-12 text-primary" />
          </div>
          <CardTitle className="text-2xl">
            {isOtpStep ? "Проверка безопасности" : "Добро пожаловать"}
          </CardTitle>
          <CardDescription>
            {isOtpStep 
              ? "Введите код, отправленный на вашу студенческую почту" 
              : "Войдите в систему с помощью учетных данных МИРЭА"}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            
            {!isOtpStep ? (
              // ШАГ 1: Ввод логина и пароля
              <>
                <div className="space-y-2">
                  <Label htmlFor="email">Email МИРЭА</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="ivanov.i.i@edu.mirea.ru"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    disabled={isLoading}
                  />
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password">Пароль</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    disabled={isLoading}
                  />
                </div>
              </>
            ) : (
              // ШАГ 2: Ввод OTP кода из письма
              <>
                <Alert className="bg-primary/10 border-primary/20 text-primary mb-4">
                  <Mail className="h-4 w-4" />
                  <AlertDescription>
                    Письмо с кодом отправлено на <b>{email}</b>. 
                  </AlertDescription>
                </Alert>
                <div className="space-y-2">
                  <Label htmlFor="otp">Код из письма</Label>
                  <Input
                    id="otp"
                    type="text"
                    placeholder="123456"
                    value={otpCode}
                    onChange={(e) => setOtpCode(e.target.value)}
                    required
                    disabled={isLoading}
                    autoComplete="one-time-code"
                    maxLength={6}
                  />
                </div>
              </>
            )}

            {error && (
              <Alert variant="destructive">
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <div className="flex gap-2">
              {isOtpStep && (
                <Button 
                  type="button" 
                  variant="outline" 
                  onClick={() => {
                    setIsOtpStep(false);
                    setOtpCode("");
                    setError("");
                  }}
                  disabled={isLoading}
                  className="px-3"
                >
                  <ArrowLeft className="h-4 w-4" />
                </Button>
              )}
              <Button type="submit" className="w-full" disabled={isLoading}>
                {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                {isOtpStep ? "Подтвердить вход" : "Войти"}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}