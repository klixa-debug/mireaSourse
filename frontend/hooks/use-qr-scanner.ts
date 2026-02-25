"use client"

import { useState, useCallback } from "react"
import { apiClient } from "@/lib/api"
import { getTelegramWebApp } from "@/lib/telegram"

export interface ScanResult {
  students: Record<string, number>
  subject: string
}

export function useQrScanner() {
  const [isScanning, setIsScanning] = useState(false)
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const webApp = getTelegramWebApp()

  const startScan = useCallback(async () => {
    setIsScanning(true)
    setError(null)
    setScanResult(null)

    try {
      if (webApp?.showScanQrPopup) {
        // Use Telegram's native QR scanner
        webApp.showScanQrPopup(
          {
            text: "Наведите камеру на QR-код для отметки посещения",
          },
          async (qrText: string) => {
            try {
              const response = await apiClient.scanQr(qrText)
              setScanResult(response.data)
              webApp.HapticFeedback?.notificationOccurred("success")
            } catch (error) {
              setError("Ошибка при сканировании QR-кода")
              webApp.HapticFeedback?.notificationOccurred("error")
            } finally {
              setIsScanning(false)
            }
          },
        )
      } else {
        // Fallback for development
        setTimeout(() => {
          setScanResult({
            students: {
              "Иванов И.И.": 4,
              "Петров П.П.": 1,
              "Сидоров С.С.": 0,
            },
            subject: "Программирование",
          })
          setIsScanning(false)
        }, 2000)
      }
    } catch (error) {
      setError("Не удалось запустить сканер")
      setIsScanning(false)
    }
  }, [webApp])

  const stopScan = useCallback(() => {
    if (webApp?.closeScanQrPopup) {
      webApp.closeScanQrPopup()
    }
    setIsScanning(false)
  }, [webApp])

  const clearResults = useCallback(() => {
    setScanResult(null)
    setError(null)
  }, [])

  return {
    isScanning,
    scanResult,
    error,
    startScan,
    stopScan,
    clearResults,
  }
}
