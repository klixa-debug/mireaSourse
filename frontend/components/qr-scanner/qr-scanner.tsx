"use client"

import { useState, useEffect } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Badge } from "@/components/ui/badge"
import { Progress } from "@/components/ui/progress"
import { getTelegramWebApp } from "@/lib/telegram"
import { apiClient } from "@/lib/api"
import { QrCode, Camera, CheckCircle, XCircle, AlertCircle, Smartphone } from "lucide-react"
import {StatusBadge} from "@/components/ui/status-badge";
import {StudentInfoHeader} from "@/components/layout/student-info-header";
import { useAuth } from "@/hooks/use-auth"

interface ScanResult {
  students: Record<string, number>
  subject: string
}

const getStatusText = (
  status: number,
): { text: string; variant: "default" | "secondary" | "destructive" | "outline" } => {
  switch (status) {
    case 0:
      return { text: "Не авторизован", variant: "destructive" }
    case 1:
      return { text: "QR устарел", variant: "destructive" }
    case 3:
      return { text: "Внутренняя ошибка", variant: "destructive" }
    case 4:
      return { text: "Отмечен", variant: "default" }
    case 5:
      return { text: "Не в университете", variant: "secondary" }
    case 6:
      return { text: "Не в расписании", variant: "secondary" }
    default:
      return { text: "Неизвестно", variant: "outline" }
  }
}

const getStatusIcon = (status: number) => {
  switch (status) {
    case 4:
      return <CheckCircle className="h-4 w-4 text-green-500" />
    case 0:
    case 1:
    case 3:
      return <XCircle className="h-4 w-4 text-red-500" />
    default:
      return <AlertCircle className="h-4 w-4 text-yellow-500" />
  }
}

interface QrScannerProps {
  onBack: () => void
}

export function QrScanner({ onBack }: QrScannerProps) {
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState("")
  const [progress, setProgress] = useState(0)

  const webApp = getTelegramWebApp()
  const { isTelegramWebApp } = useAuth()
  const startScan = () => {
    setIsScanning(true)
    setError("")
    setProgress(0)

    webApp?.showScanQrPopup?.(
        {
          text: "Наведите камеру на QR-код для отметки посещения",
        },
        async (text: string) => {
          try {
            setProgress(50)
            const response = await apiClient.scanQr(text)
            setProgress(100)

            setScanResult((prev) => {
              if (!prev) {
                return response.data
              }

              const mergedStudents: Record<string, number> = { ...prev.students }

              for (const [name, newStatus] of Object.entries(response.data.students)) {
                const oldStatus = mergedStudents[name]

                if (oldStatus === undefined) {
                  mergedStudents[name] = newStatus
                } else {
                  if (oldStatus === 4) {
                    mergedStudents[name] = 4
                  } else {
                    mergedStudents[name] = newStatus
                  }
                }
              }

              return {
                ...prev,
                students: mergedStudents,
                subject: response.data.subject || prev.subject,
              }
            })

            webApp?.HapticFeedback?.notificationOccurred("success")
          } catch (error) {
            setError("Ошибка при сканировании QR-кода. Попробуйте снова.")
            webApp?.HapticFeedback?.notificationOccurred("error")
          } finally {
            setIsScanning(false)
            setProgress(0)
          }
        },
    )
  }

  const formatName = (fullName: string): string => {
    const parts = fullName.trim().split(" ")
    if (parts.length < 2) return fullName // если имя странного формата

    const [lastName, firstName, patronymic] = parts
    const firstInitial = firstName ? `${firstName[0]}.` : ""
    const patronymicInitial = patronymic ? ` ${patronymic[0]}.` : ""

    return `${lastName} ${firstInitial}${patronymicInitial}`.trim()
  }

  const closeScan = () => {
    if (webApp?.closeScanQrPopup) {
      webApp.closeScanQrPopup()
    }
    setIsScanning(false)
  }

  useEffect(() => {
    return () => {
      if (isScanning && webApp?.closeScanQrPopup) {
        webApp.closeScanQrPopup()
      }
    }
  }, [isScanning, webApp])

  return (
      <div className="min-h-screen bg-background">
        <StudentInfoHeader/>

        <main className="container px-4 py-6 space-y-6">
          <Card>
            <CardHeader className="text-center">
              <CardTitle className="flex items-center justify-center gap-2">
                <Camera className="h-5 w-5"/>
                Сканирование QR-кода
              </CardTitle>
              <CardDescription>Наведите камеру на QR-код преподавателя для отметки посещения</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {isScanning && progress > 0 && (
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>Обработка...</span>
                      <span>{progress}%</span>
                    </div>
                    <Progress value={progress} className="w-full"/>
                  </div>
              )}

              {error && (
                  <Alert variant="destructive">
                    <AlertCircle className="h-4 w-4"/>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
              )}

              <div className="flex justify-center">
                {!isTelegramWebApp ? (
                    <div className="w-full max-w-xs space-y-4">
                      <Alert>
                        <Smartphone className="h-4 w-4" />
                        <AlertDescription>
                          Сканирование QR-кода доступно только в приложении Telegram. 
                          Пожалуйста, используйте Telegram для отметки посещения.
                        </AlertDescription>
                      </Alert>
                      <Button disabled size="lg" className="w-full">
                        <QrCode className="mr-2 h-5 w-5"/>
                        Начать сканирование
                      </Button>
                    </div>
                ) : !isScanning ? (
                    <Button onClick={startScan} size="lg" className="w-full max-w-xs">
                      <QrCode className="mr-2 h-5 w-5"/>
                      Начать сканирование
                    </Button>
                ) : (
                    <Button onClick={closeScan} variant="outline" size="lg" className="w-full max-w-xs bg-transparent">
                      Отменить
                    </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Scan Results */}
          {scanResult && (
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <CheckCircle className="h-5 w-5 text-green-500"/>
                    Результат сканирования
                  </CardTitle>
                  {scanResult.subject && (
                      <CardDescription>Предмет: {scanResult.subject}</CardDescription>
                  )}
                </CardHeader>
                <CardContent className="space-y-3">
                  {Object.entries(scanResult.students).map(([name, status]) => {
                    const statusInfo = getStatusText(status)
                    return (
                        <div key={name} className="flex items-center justify-between p-3 rounded-lg bg-muted/50">
                          <div className="flex items-center gap-3">
                            {getStatusIcon(status)}
                            <span className="font-medium">{formatName(name)}</span>
                          </div>
                          <Badge
                            variant={statusInfo.variant}
                            className={status === 4 ? "bg-green-500 text-white hover:bg-green-600" : undefined}
                          >
                            {statusInfo.text}
                          </Badge>
                        </div>
                    )
                  })}
                </CardContent>
              </Card>
          )}

          {/* Instructions */}
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Инструкция</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <div className="flex items-start gap-3">
                <div
                    className="flex-shrink-0 w-6 h-6 rounded-full bg-primary text-primary-foreground text-sm flex items-center justify-center font-semibold">
                  1
                </div>
                <div>
                  <h4 className="font-medium">Дождитесь QR-кода</h4>
                  <p className="text-sm text-muted-foreground">
                    Преподаватель покажет QR-код на экране
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div
                    className="flex-shrink-0 w-6 h-6 rounded-full bg-primary text-primary-foreground text-sm flex items-center justify-center font-semibold">
                  2
                </div>
                <div>
                  <h4 className="font-medium">Нажмите "Начать сканирование"</h4>
                  <p className="text-sm text-muted-foreground">Лучше сканировать QR-код, как только он изменится на экране. Потому что боту нужно время, чтобы всех отметить, а QR-код действует всего 5 секунд</p>
                </div>
              </div>
              <div className="flex items-start gap-3">
                <div
                    className="flex-shrink-0 w-6 h-6 rounded-full bg-primary text-primary-foreground text-sm flex items-center justify-center font-semibold">
                  3
                </div>
                <div>
                  <h4 className="font-medium">Повторно сканируйте QR-код</h4>
                  <p className="text-sm text-muted-foreground">
                    Не всех студентов с первой попытки бот успеет отметить
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </main>
      </div>
  )
}
