import { useState, useEffect } from 'react'
import { apiClient, UniversityStatus, UniversityEventDetail } from '@/lib/api'

export function useUniversityStatus() {
  const [status, setStatus] = useState<UniversityStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchStatus = async () => {
    try {
      setIsLoading(true)
      setError(null)
      const response = await apiClient.getUniversityStatus()
      setStatus(response.data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки статуса')
      console.error('Failed to fetch university status:', err)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
  }, [])

  const formatTime = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleTimeString('ru-RU', {
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getStatusText = () => {
    if (error) return 'Ошибка'
    if (!status) return 'Отсутствовал'
    
    if (status.is_in_university) {
      return 'В вузе'
    } else if (status.entry_time && status.exit_time) {
      return 'Не в вузе'
    } else {
      return 'Отсутствовал'
    }
  }

  const getStatusColor = () => {
    if (error) return 'error'
    if (!status) return 'neutral'
    
    if (status.is_in_university) {
      return 'success'
    } else if (status.entry_time && status.exit_time) {
      return 'warning'
    } else {
      return 'error'
    }
  }

  const getTimeInfo = () => {
    if (error) return null
    if (!status) return null
    
    if (status.is_in_university && status.entry_time) {
      return `Пришёл: ${formatTime(status.entry_time)}`
    } else if (status.entry_time && status.exit_time) {
      return `Присутствовал: ${formatTime(status.entry_time)} - ${formatTime(status.exit_time)}`
    } else if (status.entry_time) {
      return `Пришёл: ${formatTime(status.entry_time)}`
    }
    
    return null
  }

  const formatEventTime = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleTimeString('ru-RU', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  }

  const getEventDescription = (event: UniversityEventDetail) => {
    if (event.is_entry) {
      return `Вход в ${event.entry_location} в ${formatEventTime(event.time)}`
    } else {
      return `Выход из ${event.exit_location} в ${formatEventTime(event.time)}`
    }
  }

  const getEventsCount = () => {
    if (error) return 0
    return status?.events?.length || 0
  }

  const getEventsText = () => {
    if (error) return ''
    const count = getEventsCount()
    if (count === 0) return ''
    
    if (count === 1) {
      return '1 событие за день'
    } else if (count >= 2 && count <= 4) {
      return `${count} события за день`
    } else {
      return `${count} событий за день`
    }
  }

  return {
    status,
    isLoading,
    error,
    refetch: fetchStatus,
    getStatusText,
    getStatusColor,
    getTimeInfo,
    formatEventTime,
    getEventDescription,
    getEventsCount,
    getEventsText
  }
}
