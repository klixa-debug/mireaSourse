"use client"

import { useState, useCallback, useEffect } from "react"
import { apiClient, type Teacher, type TeacherReviews } from "@/lib/api"

export function useReviews() {
    const [allTeachers, setAllTeachers] = useState<Teacher[]>([])
    const [isLoadingTeachers, setIsLoadingTeachers] = useState(true)
    const [searchResults, setSearchResults] = useState<Teacher[]>([])
    const [isSearching, setIsSearching] = useState(false)
    const [teacherReviews, setTeacherReviews] = useState<TeacherReviews | null>(null)
    const [isLoadingReviews, setIsLoadingReviews] = useState(false)
    const [isSubmitting, setIsSubmitting] = useState(false)
    const [error, setError] = useState("")

    const clearError = useCallback(() => setError(""), [])

    const loadAllTeachers = useCallback(async () => {
        setIsLoadingTeachers(true)
        try {
            const res = await apiClient.getAllTeachers()
            setAllTeachers(res.data ?? [])
        } catch {
            setAllTeachers([])
        } finally {
            setIsLoadingTeachers(false)
        }
    }, [])

    useEffect(() => {
        loadAllTeachers()
    }, [loadAllTeachers])

    const searchTeachers = useCallback(async (query: string) => {
        if (query.trim().length < 2) {
            setSearchResults([])
            return
        }

        setIsSearching(true)
        setError("")
        try {
            const res = await apiClient.searchTeachers(query.trim())
            setSearchResults(res.data ?? [])
        } catch {
            setSearchResults([])
        } finally {
            setIsSearching(false)
        }
    }, [])

    const addTeacher = useCallback(async (name: string): Promise<Teacher | null> => {
        setError("")
        try {
            const res = await apiClient.addTeacher(name.trim())
            return res.data
        } catch {
            setError("Не удалось добавить преподавателя")
            return null
        }
    }, [])

    const loadReviews = useCallback(async (teacherId: number) => {
        setIsLoadingReviews(true)
        setError("")
        try {
            const res = await apiClient.getTeacherReviews(teacherId)
            setTeacherReviews(res.data)
        } catch {
            setError("Не удалось загрузить отзывы")
        } finally {
            setIsLoadingReviews(false)
        }
    }, [])

    const createReview = useCallback(async (teacherId: number, comment: string): Promise<boolean> => {
        setIsSubmitting(true)
        setError("")
        try {
            await apiClient.createReview(teacherId, comment)
            await loadReviews(teacherId)
            return true
        } catch (err: any) {
            const msg = err?.message || ""
            if (msg.includes("409")) {
                setError("Вы уже оставили отзыв на этого преподавателя")
            } else {
                setError("Не удалось оставить отзыв")
            }
            return false
        } finally {
            setIsSubmitting(false)
        }
    }, [loadReviews])

    const deleteReview = useCallback(async (teacherId: number): Promise<boolean> => {
        setIsSubmitting(true)
        setError("")
        try {
            await apiClient.deleteReview(teacherId)
            await loadReviews(teacherId)
            return true
        } catch {
            setError("Не удалось удалить отзыв")
            return false
        } finally {
            setIsSubmitting(false)
        }
    }, [loadReviews])

    const resetTeacher = useCallback(() => {
        setTeacherReviews(null)
        setError("")
    }, [])

    return {
        allTeachers,
        isLoadingTeachers,
        searchResults,
        isSearching,
        teacherReviews,
        isLoadingReviews,
        isSubmitting,
        error,
        clearError,
        searchTeachers,
        addTeacher,
        loadReviews,
        createReview,
        deleteReview,
        resetTeacher,
        loadAllTeachers,
    }
}
