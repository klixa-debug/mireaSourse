// Telegram WebApp API integration
export interface TelegramUser {
  id: number
  first_name: string
  last_name?: string
  username?: string
  language_code?: string
}

export interface TelegramWebApp {
  initData: string
  initDataUnsafe: {
    user?: TelegramUser
    chat_instance?: string
    chat_type?: string
    start_param?: string
    auth_date?: number
    hash?: string
  }
  version: string
  platform: string
  colorScheme: "light" | "dark"
  themeParams: {
    bg_color?: string
    text_color?: string
    hint_color?: string
    link_color?: string
    button_color?: string
    button_text_color?: string
  }
  isExpanded: boolean
  viewportHeight: number
  viewportStableHeight: number
  headerColor: string
  backgroundColor: string
  isClosingConfirmationEnabled: boolean
  ready: () => void
  expand: () => void
  close: () => void
  MainButton: {
    text: string
    color: string
    textColor: string
    isVisible: boolean
    isActive: boolean
    isProgressVisible: boolean
    setText: (text: string) => void
    onClick: (callback: () => void) => void
    show: () => void
    hide: () => void
    enable: () => void
    disable: () => void
    showProgress: (leaveActive?: boolean) => void
    hideProgress: () => void
    setParams: (params: any) => void
  }
  BackButton: {
    isVisible: boolean
    onClick: (callback: () => void) => void
    show: () => void
    hide: () => void
  }
  HapticFeedback: {
    impactOccurred: (style: "light" | "medium" | "heavy" | "rigid" | "soft") => void
    notificationOccurred: (type: "error" | "success" | "warning") => void
    selectionChanged: () => void
  }
  showPopup: (
    params: {
      title?: string
      message: string
      buttons?: Array<{
        id?: string
        type?: "default" | "ok" | "close" | "cancel" | "destructive"
        text?: string
      }>
    },
    callback?: (buttonId: string) => void,
  ) => void
  showAlert: (message: string, callback?: () => void) => void
  showConfirm: (message: string, callback?: (confirmed: boolean) => void) => void
  showScanQrPopup: (
    params: {
      text?: string
    },
    callback?: (text: string) => void,
  ) => void
  closeScanQrPopup: () => void
}

declare global {
  interface Window {
    Telegram?: {
      WebApp: TelegramWebApp
    }
  }
}

export const getTelegramWebApp = (): TelegramWebApp | null => {
  if (typeof window !== "undefined" && window.Telegram?.WebApp) {
    return window.Telegram.WebApp
  }
  return null
}

// Проверка, находится ли пользователь в Telegram Mini App
export const isTelegramMiniApp = (): boolean => {
  if (typeof window === "undefined") return false
  
  // Проверяем наличие объекта Telegram WebApp
  const hasWebApp = !!window.Telegram?.WebApp
  
  if (!hasWebApp) {
    // Дополнительная проверка через User-Agent (на случай, если скрипт еще не загрузился)
    const userAgent = navigator.userAgent || navigator.vendor || (window as any).opera
    const isTelegramUserAgent = /Telegram/i.test(userAgent)
    
    // Также проверяем наличие параметров в URL, которые Telegram добавляет
    const urlParams = new URLSearchParams(window.location.search)
    const hasTelegramParams = urlParams.has('tgWebAppStartParam') || urlParams.has('tgWebAppData')
    
    return isTelegramUserAgent || hasTelegramParams
  }
  
  // Проверяем наличие initData или initDataUnsafe
  const webApp = window.Telegram.WebApp
  const hasInitData = !!(webApp.initData || webApp.initDataUnsafe)
  
  // Также проверяем platform - в Telegram Mini App это обычно "ios", "android", "web", "tdesktop" и т.д.
  const hasPlatform = !!webApp.platform
  
  return hasInitData || hasPlatform
}

export const initTelegramWebApp = () => {
  const webApp = getTelegramWebApp()
  if (webApp) {
    webApp.ready()
    webApp.expand()

    if (webApp.themeParams) {
      const root = document.documentElement
      if (webApp.themeParams.bg_color) {
        root.style.setProperty("--telegram-bg", webApp.themeParams.bg_color)
      }
      if (webApp.themeParams.text_color) {
        root.style.setProperty("--telegram-text", webApp.themeParams.text_color)
      }
      if (webApp.themeParams.button_color) {
        root.style.setProperty("--telegram-button", webApp.themeParams.button_color)
      }
    }

    return webApp
  }
  return null
}

export const useTelegramTheme = () => {
  const webApp = getTelegramWebApp()
  return {
    colorScheme: webApp?.colorScheme || "light",
    themeParams: webApp?.themeParams || {},
    platform: webApp?.platform || "unknown",
  }
}
