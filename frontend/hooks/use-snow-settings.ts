"use client"

import { useState, useEffect, useCallback } from "react"

const SNOW_ENABLED_KEY = "snow_enabled"

export function useSnowSettings() {
  const [snowEnabled, setSnowEnabledState] = useState<boolean>(true)

  // Функция для чтения значения из localStorage
  const readFromStorage = useCallback(() => {
    if (typeof window === "undefined") return true
    const stored = localStorage.getItem(SNOW_ENABLED_KEY)
    return stored !== null ? stored === "true" : true
  }, [])

  useEffect(() => {
    // Загружаем настройку из localStorage при монтировании
    setSnowEnabledState(readFromStorage())

    // Слушаем изменения в localStorage (для синхронизации между вкладками)
    const handleStorageChange = (e: StorageEvent) => {
      if (e.key === SNOW_ENABLED_KEY) {
        setSnowEnabledState(e.newValue === "true")
      }
    }

    window.addEventListener("storage", handleStorageChange)

    // Также слушаем изменения в текущей вкладке через кастомное событие
    const handleCustomStorageChange = () => {
      setSnowEnabledState(readFromStorage())
    }

    window.addEventListener("snowSettingsChanged", handleCustomStorageChange)

    return () => {
      window.removeEventListener("storage", handleStorageChange)
      window.removeEventListener("snowSettingsChanged", handleCustomStorageChange)
    }
  }, [readFromStorage])

  const setSnowEnabled = useCallback((enabled: boolean) => {
    setSnowEnabledState(enabled)
    localStorage.setItem(SNOW_ENABLED_KEY, enabled.toString())
    // Отправляем кастомное событие для синхронизации в текущей вкладке
    window.dispatchEvent(new Event("snowSettingsChanged"))
  }, [])

  return {
    snowEnabled,
    setSnowEnabled,
  }
}

