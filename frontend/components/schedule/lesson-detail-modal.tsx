"use client"

import type React from "react"

import { useState, useEffect } from "react"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent } from "@/components/ui/card"
import { apiClient, type Lesson, type AttendanceRecord } from "@/lib/api"
import { Clock, MapPin, User, Users, CheckCircle, XCircle } from "lucide-react"
import { format } from "date-fns"
import { ru } from "date-fns/locale"

interface LessonDetailModalProps {
  lesson: Lesson
  children: React.ReactNode
}

const formatTime = (timestamp: number) => {
  return format(new Date(timestamp * 1000), "HH:mm")
}

const formatDate = (timestamp: number) => {
  return format(new Date(timestamp * 1000), "d MMMM yyyy", { locale: ru })
}

export function LessonDetailModal({ lesson, children }: LessonDetailModalProps) {
  const [attendance, setAttendance] = useState<AttendanceRecord[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [isOpen, setIsOpen] = useState(false)

  const loadAttendance = async () => {
    if (!isOpen) return

    setIsLoading(true)
    try {
      const response = await apiClient.getAttendance(lesson.uuid)
      setAttendance(response.data)
    } catch (error) {
      console.error("Failed to load attendance:", error)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    loadAttendance()
  }, [isOpen, lesson.uuid])

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

  return (
    <Dialog open={isOpen} onOpenChange={setIsOpen}>
      <DialogTrigger asChild>{children}</DialogTrigger>
      <DialogContent className="max-w-md max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Badge className={getLessonTypeColor(lesson.type)}>{lesson.type}</Badge>
            {lesson.title}
          </DialogTitle>
          <DialogDescription>{formatDate(lesson.start)}</DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          <Card>
            <CardContent className="p-4 space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <span>
                  {formatTime(lesson.start)} - {formatTime(lesson.end)}
                </span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <MapPin className="h-4 w-4 text-muted-foreground" />
                <span>
                  {lesson.auditorium} • Корпус {lesson.campus}
                </span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <User className="h-4 w-4 text-muted-foreground" />
                <span>{lesson.teacher}</span>
              </div>
              {lesson.groups.length > 1 ? (
                  <div className="flex items-center gap-2 text-sm">
                    <Users className="h-4 w-4 text-muted-foreground"/>
                    <span>{lesson.groups.join(", ")}</span>
                  </div>
              ) : <></>}
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Посещаемость</span>
                <Badge variant={lesson.status ? "default" : "secondary"}>
                  {lesson.status ? "Активно" : "Завершено"}
                </Badge>
              </div>
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <span>Присутствует: {lesson.attended}</span>
                <span>Всего: {lesson.total}</span>
                <span>{lesson.total > 0 ? Math.round((lesson.attended / lesson.total) * 100) : 0}%</span>
              </div>
            </CardContent>
          </Card>

          {attendance.length > 0 && (
            <Card>
              <CardContent className="p-4">
                <h4 className="font-medium mb-3">Список присутствующих</h4>
                {isLoading ? (
                  <div className="text-center py-4">
                    <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary mx-auto mb-2"></div>
                    <p className="text-sm text-muted-foreground">Загрузка...</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {attendance.map((record, index) => (
                      <div key={index} className="flex items-center justify-between p-2 rounded-lg bg-muted/50">
                        <div className="flex items-center gap-2">
                          {record.status > 0 ? (
                            <CheckCircle className="h-4 w-4 text-green-500" />
                          ) : (
                            <XCircle className="h-4 w-4 text-red-500" />
                          )}
                          <span className="text-sm">{record.fullname}</span>
                          {record.is_elder && (
                            <Badge variant="outline" size="sm">
                              Староста
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
