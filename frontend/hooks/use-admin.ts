import { useAuth } from "./use-auth"
import { useMemo } from "react"

// ID админа - должен совпадать с ADMIN_USER_ID в конфигурации бэкенда
// Для тестирования можно установить значение по умолчанию
const ADMIN_USER_ID = process.env.NEXT_PUBLIC_ADMIN_USER_ID ? parseInt(process.env.NEXT_PUBLIC_ADMIN_USER_ID) : 8574412273

export function useAdmin() {
  const { user, isAuthenticated } = useAuth()
  
  const isAdmin = useMemo(() => {
    if (!isAuthenticated || !user || !ADMIN_USER_ID) {
      return false
    }
    return user.telegram_id === ADMIN_USER_ID
  }, [user, isAuthenticated])

  return {
    isAdmin,
    isAuthenticated,
    user
  }
}
