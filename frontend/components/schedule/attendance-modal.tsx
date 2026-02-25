"use client"

import { useState, useEffect } from "react"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { apiClient, type Lesson, type AttendanceRecord } from "@/lib/api"
import { CheckCircle, XCircle, Users } from "lucide-react"
import { format } from "date-fns"
import { ru } from "date-fns/locale"

interface AttendanceModalProps {
    lesson: Lesson | null
    isOpen: boolean
    onClose: () => void
}

const formatTime = (timestamp: number) => {
    return format(new Date(timestamp * 1000), "HH:mm")
}

const formatDate = (timestamp: number) => {
    return format(new Date(timestamp * 1000), "d MMMM yyyy", { locale: ru })
}

export function AttendanceModal({ lesson, isOpen, onClose }: AttendanceModalProps) {
    const [attendance, setAttendance] = useState<AttendanceRecord[]>([])
    const [isLoading, setIsLoading] = useState(false)

    const loadAttendance = async () => {
        if (!lesson || !isOpen) return

        setIsLoading(true)
        try {
            const response = await apiClient.getAttendance(lesson.uuid)
            setAttendance(response.data)
        } catch (error) {
            console.error("Failed to load attendance:", error)
            setAttendance([])
        } finally {
            setIsLoading(false)
        }
    }

    useEffect(() => {
        loadAttendance()
    }, [isOpen, lesson?.uuid])

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

    if (!lesson) return null

    const presentStudents = attendance.filter((record) => record.status === 2)
    const absentStudents = attendance.filter((record) => record.status === 1)

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-md max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                    <DialogTitle className="text-left flex gap-2">
                        <Badge className={getLessonTypeColor(lesson.type)}>{lesson.type}</Badge>
                        {lesson.title}
                    </DialogTitle>
                    <DialogDescription className="text-left">
                        {formatDate(lesson.start)} • {formatTime(lesson.start)} - {formatTime(lesson.end)}
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-4">
                    {/* Attendance Stats */}
                    <Card>
                        <CardContent className="p-4">
                            <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  Посещаемость
                </span>
                                <Badge variant={lesson.status ? "default" : "destructive"}>
                                    {lesson.status ? "Отмечен" : "Пропуск"}
                                </Badge>
                            </div>
                            <div className="grid grid-cols-3 gap-4 text-center">
                                <div>
                                    <div className="text-lg font-semibold text-green-600">{presentStudents.length}</div>
                                    <div className="text-xs text-muted-foreground">Присутствует</div>
                                </div>
                                <div>
                                    <div className="text-lg font-semibold text-red-600">{absentStudents.length}</div>
                                    <div className="text-xs text-muted-foreground">Отсутствует</div>
                                </div>
                                <div>
                                    <div className="text-lg font-semibold">{attendance.length}</div>
                                    <div className="text-xs text-muted-foreground">Всего</div>
                                </div>
                            </div>

                            <div>
                                {/* Attendance List  */}
                                {isLoading ? (
                                    <div className="p-8 text-center">
                                        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary mx-auto mb-2"></div>
                                        <p className="text-sm text-muted-foreground">Загрузка списка...</p>
                                    </div>
                                ) : attendance.length === 0 ? (
                                    <div className="p-8 text-center">
                                        <Users className="h-12 w-12 text-muted-foreground mx-auto mb-4"/>
                                        <h3 className="text-lg font-semibold mb-2">Данные отсутствуют</h3>
                                        <p className="text-muted-foreground text-sm">Информация о посещаемости пока недоступна</p>
                                    </div>
                                ) : (
                                    <div className="mt-2">
                                        <div className="hidden bg-red-50 dark:bg-red-900/20 bg-green-50 dark:bg-green-900/20"></div>
                                        {attendance.length > 0 && (
                                            <div className="space-y-2 max-h-64 overflow-y-auto">
                                                {attendance.map((record, index) => (
                                                    <div
                                                        key={index}
                                                        className={`flex items-center justify-between p-2 rounded-lg bg-${record.status === 1 ? 'red' : 'green'}-50 dark:bg-${record.status === 1 ? 'red' : 'green'}-900/20`}
                                                    >
                                                        <span className="text-sm">{record.fullname}</span>
                                                        {record.is_elder && (
                                                            <Badge variant="outline" size="sm">
                                                                Староста
                                                            </Badge>
                                                        )}
                                                    </div>
                                                ))}
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        </CardContent>
                    </Card>
                </div>
            </DialogContent>
        </Dialog>
    )
}
