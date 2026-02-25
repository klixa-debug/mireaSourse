"use client"

import { useState } from "react"
import { apiClient, type Lesson } from "@/lib/api"
import { startOfWeek, endOfWeek, eachDayOfInterval } from "date-fns"

export function useSchedule() {
  const [lessons, setLessons] = useState<Lesson[]>([])
  const [weekLessons, setWeekLessons] = useState<Record<string, Lesson[]>>({})
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadDayLessons = async (date: Date) => {
    setIsLoading(true)
    setError(null)

    try {
      const response = await apiClient.getLessons(date.getFullYear(), date.getMonth() + 1, date.getDate())
      setLessons(response.data)
    } catch (error) {
      setError("Не удалось загрузить расписание")
    } finally {
      setIsLoading(false)
    }
  }

  const loadWeekLessons = async (date: Date) => {
    setIsLoading(true)
    setError(null)

    try {
      const weekStart = startOfWeek(date, { weekStartsOn: 1 })
      const weekEnd = endOfWeek(date, { weekStartsOn: 1 })
      const weekDays = eachDayOfInterval({ start: weekStart, end: weekEnd })

      const weekData: Record<string, Lesson[]> = {}

      for (const day of weekDays) {
        const response = await apiClient.getLessons(day.getFullYear(), day.getMonth() + 1, day.getDate())
        weekData[day.toISOString().split("T")[0]] = response.data
      }

      setWeekLessons(weekData)
    } catch (error) {
      setError("Не удалось загрузить расписание на неделю")
    } finally {
      setIsLoading(false)
    }
  }

  const getTodayLessons = async () => {
    const today = new Date()
    await loadDayLessons(today)
    return lessons
  }

  return {
    lessons,
    weekLessons,
    isLoading,
    error,
    loadDayLessons,
    loadWeekLessons,
    getTodayLessons,
  }
}
