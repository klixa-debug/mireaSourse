"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Progress } from "@/components/ui/progress"
import { getTelegramWebApp } from "@/lib/telegram"
import { apiClient } from "@/lib/api"
import { useAuth } from "@/hooks/use-auth"
import { CheckCircle, AlertCircle, Shield, Loader2, ChevronDown, ChevronUp } from "lucide-react"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"

interface TotpSetupProps {
  onComplete: () => void
  onBack?: () => void
}

function base32Decode(encoded: string): Uint8Array {
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  let bits = 0
  let value = 0
  let index = 0
  const output: number[] = []

  for (let i = 0; i < encoded.length; i++) {
    const char = encoded[i].toUpperCase()
    if (char === "=") break // Padding
    const charIndex = base32Chars.indexOf(char)
    if (charIndex === -1) continue

    value = (value << 5) | charIndex
    bits += 5

    if (bits >= 8) {
      output[index++] = (value >> (bits - 8)) & 0xff
      bits -= 8
    }
  }

  return new Uint8Array(output)
}

async function generateTotpCode(secret: string): Promise<string> {
  const time = Math.floor(Date.now() / 1000 / 30)

  const timeBuffer = new ArrayBuffer(8)
  const timeView = new DataView(timeBuffer)
  timeView.setBigUint64(0, BigInt(time), false) // Big-endian

  const keyBytes = base32Decode(secret)

  const key = await crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"]
  )

  const signature = await crypto.subtle.sign("HMAC", key, timeBuffer)
  const sigArray = new Uint8Array(signature)

  const offset = sigArray[sigArray.length - 1] & 0x0f
  const code = ((sigArray[offset] & 0x7f) << 24 |
    (sigArray[offset + 1] & 0xff) << 16 |
    (sigArray[offset + 2] & 0xff) << 8 |
    (sigArray[offset + 3] & 0xff)) % 1000000

  return code.toString().padStart(6, "0")
}

function isValidBase32Secret(secret: string): boolean {
  const base32Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  const cleaned = secret.replace(/\s/g, "").toUpperCase()
  
  if (cleaned.length < 16) return false
  
  for (let i = 0; i < cleaned.length; i++) {
    if (base32Chars.indexOf(cleaned[i]) === -1) {
      return false
    }
  }
  
  return true
}

export function TotpSetup({ onComplete, onBack }: TotpSetupProps) {
  const [secretInput, setSecretInput] = useState("")
  const [secret, setSecret] = useState<string | null>(null)
  const [totpCode, setTotpCode] = useState<string | null>(null)
  const [error, setError] = useState("")
  const [isVerifying, setIsVerifying] = useState(false)
  const [progress, setProgress] = useState(100)
  const [isValidating, setIsValidating] = useState(false)
  const [isInstructionsOpen, setIsInstructionsOpen] = useState(false)
  const { refreshUser, user } = useAuth()

  const webApp = getTelegramWebApp()

  const handleSecretInput = async (value: string) => {
    setSecretInput(value)
    setError("")

    const cleanedSecret = value.replace(/\s/g, "").toUpperCase()

    if (cleanedSecret.length >= 16) {
      setIsValidating(true)
      
      if (!isValidBase32Secret(cleanedSecret)) {
        setError("Неверный формат секретного ключа. Используйте только буквы A-Z и цифры 2-7")
        setIsValidating(false)
        return
      }

      try {
        const code = await generateTotpCode(cleanedSecret)
        setSecret(cleanedSecret)
        setTotpCode(code)
        setError("")
        webApp?.HapticFeedback?.notificationOccurred("success")
      } catch (error) {
        setError("Ошибка при обработке секретного ключа. Проверьте правильность ввода.")
        webApp?.HapticFeedback?.notificationOccurred("error")
      } finally {
        setIsValidating(false)
      }
    } else if (secret) {
      setSecret(null)
      setTotpCode(null)
    }
  }

  const handleVerifyAndSave = async () => {
    if (!secret) return

    setIsVerifying(true)
    setError("")

    try {
      await apiClient.updateTotpSecret({ totp_secret: secret })

      await refreshUser()

      onComplete()
      webApp?.HapticFeedback?.notificationOccurred("success")
    } catch (error: any) {
      const errorMessage = error?.message || error?.toString() || ""
      if (errorMessage.includes("totp_secret_required") || 
          errorMessage.includes("invalid_credentials") ||
          errorMessage.includes("Неверный логин")) {
        setError("Неверный секретный ключ. Проверьте правильность ввода и попробуйте снова.")
      } else {
        setError("Ошибка при проверке авторизации. Попробуйте снова.")
      }
      webApp?.HapticFeedback?.notificationOccurred("error")
    } finally {
      setIsVerifying(false)
    }
  }

  useEffect(() => {
    if (!secret) {
      setProgress(100)
      return
    }

    const updateCode = async () => {
      try {
        const code = await generateTotpCode(secret)
        setTotpCode(code)
        setProgress(100)
      } catch (error) {
        console.error("Failed to generate TOTP code:", error)
      }
    }

    updateCode()

    const progressInterval = setInterval(() => {
      const now = Date.now()
      const timeInPeriod = Math.floor(now / 1000) % 30
      const remaining = 30 - timeInPeriod
      const progressValue = (remaining / 30) * 100
      setProgress(progressValue)
    }, 1000)

    const codeInterval = setInterval(updateCode, 30000)

    return () => {
      clearInterval(progressInterval)
      clearInterval(codeInterval)
    }
  }, [secret])

  return (
    <div className="flex items-center justify-center p-4 min-h-0">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center pb-3">
          <div className="flex justify-center mb-2">
            <Shield className="h-10 w-10 text-primary" />
          </div>
          <CardTitle className="text-xl">Настройка двухфакторной авторизации</CardTitle>
          <CardDescription className="text-sm mt-1">
            Привяжите двухфакторный ключ для авторизации в МИРЭА
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3 pt-0 pb-4">
          {error && (
            <Alert variant="destructive" className="py-2">
              <AlertCircle className="h-4 w-4" />
              <AlertDescription className="text-sm">{error}</AlertDescription>
            </Alert>
          )}

          <div className="space-y-2">
            <Label htmlFor="secret">Секретный ключ</Label>
            <div className="relative">
              <Input
                id="secret"
                type="text"
                placeholder="Введите секретный ключ (Base32)"
                value={secretInput}
                onChange={(e) => handleSecretInput(e.target.value)}
                className="font-mono text-sm"
                autoFocus
                disabled={isValidating}
              />
              {isValidating && (
                <div className="absolute right-3 top-1/2 -translate-y-1/2">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              )}
            </div>
            <p className="text-xs text-muted-foreground">
              Бот будет эмулировать ваше устройство, для автоматического входа
            </p>
          </div>

          <Collapsible open={isInstructionsOpen} onOpenChange={setIsInstructionsOpen}>
            <CollapsibleTrigger asChild>
              <Button variant="ghost" size="sm" className="w-full justify-between text-xs">
                <span>Как получить секретный ключ?</span>
                {isInstructionsOpen ? (
                  <ChevronUp className="h-4 w-4" />
                ) : (
                  <ChevronDown className="h-4 w-4" />
                )}
              </Button>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-2 pt-2">
              <div className="rounded-lg border bg-muted/50 p-3 space-y-2 text-xs">
                <ol className="list-decimal list-inside space-y-1.5 text-muted-foreground">
                  <li>Перейдите на сайт <span className="font-mono text-foreground">sso.mirea.ru</span></li>
                  <li>Нажмите кнопку <span className="font-semibold text-foreground">Добавить</span></li>
                  <li>Под QR кодом будет ссылка <span className="font-semibold text-foreground">"Не удается выполнить сканирование?"</span></li>
                  <li>При переходе по ссылке появится код из 8 слов по 4 буквы</li>
                  <li>Вставьте этот код в поле выше</li>
                </ol>
              </div>
            </CollapsibleContent>
          </Collapsible>

          {secret && (
            <div className="space-y-3 pt-2 border-t">
              <div className="text-center space-y-2">
                <p className="text-sm text-muted-foreground">Код подтверждения:</p>
                <Badge variant="outline" className="text-xl font-mono px-3 py-1.5">
                  {totpCode || "..."}
                </Badge>
                
                {/* Прогресс бар */}
                <div className="space-y-1">
                  <Progress value={progress} className="w-full h-1.5" />
                  <p className="text-xs text-muted-foreground">
                    Обновление через {Math.ceil((progress / 100) * 30)} сек
                  </p>
                </div>
                
                <p className="text-xs text-muted-foreground">
                  Введите этот код в личном кабинете МИРЭА для добавления, затем нажмите кнопку ниже
                </p>
              </div>

              <Alert className="bg-blue-50 dark:bg-blue-950/20 border-blue-200 dark:border-blue-800">
                <AlertCircle className="h-4 w-4 text-blue-600 dark:text-blue-400" />
                <AlertDescription className="text-sm text-blue-900 dark:text-blue-100">
                  <span className="font-semibold">Важно:</span> Укажите название устройства <span className="font-mono font-semibold">"Google Android"</span> Иначе бот не сможет авторизоваться.
                </AlertDescription>
              </Alert>

              <Button 
                onClick={handleVerifyAndSave} 
                className="w-full" 
                size="sm"
                disabled={isVerifying}
              >
                {isVerifying && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
                Я привязал аутентификатор
              </Button>
            </div>
          )}

          {onBack && (
            <Button onClick={onBack} variant="outline" className="w-full" size="sm">
              Назад
            </Button>
          )}
        </CardContent>
      </Card>
    </div>
  )
}



