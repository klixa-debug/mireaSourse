"use client"

import { useState } from "react"
import { apiClient, type DisciplinesResponse } from "@/lib/api"

export function usePerformance() {
  const [disciplinesData, setDisciplinesData] = useState<DisciplinesResponse | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadDisciplines = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const response = await apiClient.getDisciplines()
      setDisciplinesData(response.data)
    } catch (error) {
      setError("Не удалось загрузить данные об успеваемости")
    } finally {
      setIsLoading(false)
    }
  }

  const getAverageGrade = () => {
    if (!disciplinesData?.disciplines.length) return 0
    return disciplinesData.disciplines.reduce((sum, d) => sum + d.total, 0) / disciplinesData.disciplines.length
  }

  const getGroupAverageGrade = () => {
    if (!disciplinesData?.disciplines.length) return 0
    return disciplinesData.disciplines.reduce((sum, d) => sum + d.avg_group, 0) / disciplinesData.disciplines.length
  }

  const getPerformanceComparison = () => {
    const studentAvg = getAverageGrade()
    const groupAvg = getGroupAverageGrade()
    return {
      student: studentAvg,
      group: groupAvg,
      difference: studentAvg - groupAvg,
      isAboveAverage: studentAvg > groupAvg,
    }
  }

  const getBestSubjects = (limit = 3) => {
    if (!disciplinesData?.disciplines.length) return []
    return [...disciplinesData.disciplines].sort((a, b) => b.total - a.total).slice(0, limit)
  }

  const getWorstSubjects = (limit = 3) => {
    if (!disciplinesData?.disciplines.length) return []
    return [...disciplinesData.disciplines].sort((a, b) => a.total - b.total).slice(0, limit)
  }

  return {
    disciplinesData,
    isLoading,
    error,
    loadDisciplines,
    getAverageGrade,
    getGroupAverageGrade,
    getPerformanceComparison,
    getBestSubjects,
    getWorstSubjects,
  }
}
