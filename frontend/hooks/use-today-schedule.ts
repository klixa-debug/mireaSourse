import { useState, useEffect } from 'react'
import { apiClient, Lesson } from '@/lib/api'

export function useTodaySchedule() {
  const [lessons, setLessons] = useState<Lesson[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchTodayLessons = async () => {
    try {
      setIsLoading(true)
      setError(null)
      
      const today = new Date()
      const response = await apiClient.getLessons(
        today.getFullYear(), 
        today.getMonth() + 1, 
        today.getDate()
      )
      
      setLessons(response.data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Ошибка загрузки расписания')
      console.error('Failed to fetch today schedule:', err)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchTodayLessons()
  }, [])

  const formatTime = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleTimeString('ru-RU', {
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  const getLessonTypeColor = (type: string) => {
    switch (type) {
      case "ЛК":
        return "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
      case "ПР":
        return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
      case "ЛБ":
        return "bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200"
      default:
        return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"
    }
  }

  const getLessonTypeText = (type: string) => {
    switch (type) {
      case "ЛК":
        return "Лекция"
      case "ПР":
        return "Практика"
      case "ЛБ":
        return "Лабораторная"
      default:
        return "Занятие"
    }
  }

  const getCurrentLesson = () => {
    const now = new Date()
    const currentTime = now.getTime() / 1000 // Convert to Unix timestamp
    
    return lessons.find(lesson => 
      currentTime >= lesson.start && currentTime <= lesson.end
    )
  }

  const getNextLesson = () => {
    const now = new Date()
    const currentTime = now.getTime() / 1000
    
    return lessons.find(lesson => lesson.start > currentTime)
  }

  const getUpcomingLessons = () => {
    const now = new Date()
    const currentTime = now.getTime() / 1000
    
    return lessons.filter(lesson => lesson.start > currentTime)
  }

  const getCompletedLessons = () => {
    const now = new Date()
    const currentTime = now.getTime() / 1000
    
    return lessons.filter(lesson => lesson.end < currentTime)
  }

  return {
    lessons,
    isLoading,
    error,
    refetch: fetchTodayLessons,
    formatTime,
    getLessonTypeColor,
    getLessonTypeText,
    getCurrentLesson,
    getNextLesson,
    getUpcomingLessons,
    getCompletedLessons
  }
}
