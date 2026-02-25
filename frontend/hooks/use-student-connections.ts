"use client"

import { useState } from "react"
import { apiClient, type Student } from "@/lib/api"

export function useStudentConnections() {
  const [connectedStudents, setConnectedStudents] = useState<Student[]>([])
  const [connectedToUser, setConnectedToUser] = useState<Student[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadConnectedStudents = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const response = await apiClient.listConnectedStudents()
      setConnectedStudents(response.data)
    } catch (error) {
      setError("Не удалось загрузить список студентов")
    } finally {
      setIsLoading(false)
    }
  }

  const loadConnectedToUser = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const response = await apiClient.listConnectedToUser()
      setConnectedToUser(response.data)
    } catch (error) {
      setError("Не удалось загрузить список пользователей")
    } finally {
      setIsLoading(false)
    }
  }

  const loadAll = async () => {
    await Promise.all([loadConnectedStudents(), loadConnectedToUser()])
  }

  const findStudent = async (email: string): Promise<Student | null> => {
    try {
      const response = await apiClient.findStudent(email)
      return response.data
    } catch (error) {
      throw new Error("Студент не найден")
    }
  }

  const connectStudent = async (email: string) => {
    try {
      await apiClient.connectStudent(email)
      await loadAll() // Refresh both lists
    } catch (error) {
      throw new Error("Не удалось добавить студента")
    }
  }

  const toggleStudent = async (email: string) => {
    try {
      await apiClient.toggleConnectedStudent(email)
      await loadConnectedStudents() // Refresh the list
    } catch (error) {
      throw new Error("Не удалось изменить статус студента")
    }
  }

  const disconnectStudent = async (email: string) => {
    try {
      await apiClient.disconnectStudent(email)
      await loadAll() // Refresh both lists
    } catch (error) {
      throw new Error("Не удалось отвязать студента")
    }
  }

  const disconnectFromUser = async (email: string) => {
    try {
      await apiClient.disconnectFromUser(email)
      await loadAll() // Refresh both lists
    } catch (error) {
      throw new Error("Не удалось отвязаться от пользователя")
    }
  }

  const getActiveStudents = () => {
    return connectedStudents.filter((student) => student.enabled)
  }

  const getInactiveStudents = () => {
    return connectedStudents.filter((student) => !student.enabled)
  }

  return {
    connectedStudents,
    connectedToUser,
    isLoading,
    error,
    loadConnectedStudents,
    loadConnectedToUser,
    loadAll,
    findStudent,
    connectStudent,
    toggleStudent,
    disconnectStudent,
    disconnectFromUser,
    getActiveStudents,
    getInactiveStudents,
  }
}
