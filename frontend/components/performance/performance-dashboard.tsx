"use client"

import { useState, useEffect } from "react"
import { Card, CardContent } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { apiClient, type DisciplinesResponse } from "@/lib/api"
import {
  GraduationCap,
  ArrowLeft,
  Award,
  Target,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
} from "lucide-react"
import { StudentInfoHeader } from "@/components/layout/student-info-header"

interface PerformanceDashboardProps {
  onBack: () => void
}

const getGradeInfo = (points: number, isDisqualified: boolean = false) => {
  // Если есть недопуск, не показываем статус "Зачет/Автомат"
  if (isDisqualified) {
    // Используем цвет destructive (бордовый) как у бейджа недопуска
    const disqualifiedColor = "text-destructive"
    if (points >= 80)
      return {
        grade: 5,
        status: "Отлично",
        color: disqualifiedColor,
        bgColor: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
        showBadge: false, // Скрываем бейдж, так как есть недопуск
      }
    if (points >= 60)
      return {
        grade: 4,
        status: "Хорошо",
        color: disqualifiedColor,
        bgColor: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
        showBadge: false,
      }
    if (points >= 40)
      return {
        grade: 3,
        status: "Зачет/Автомат",
        color: disqualifiedColor,
        bgColor: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
        showBadge: false, // Скрываем бейдж "Автомат" при недопуске
      }
    return {
      grade: 2,
      status: "Неудовлетворительно",
      color: disqualifiedColor,
      bgColor: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
      showBadge: false,
    }
  }

  // Обычная логика без недопуска
  if (points >= 80)
    return {
      grade: 5,
      status: "Отлично",
      color: "text-green-600 dark:text-green-400",
      bgColor: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      showBadge: true,
    }
  if (points >= 60)
    return {
      grade: 4,
      status: "Хорошо",
      color: "text-green-600 dark:text-green-400",
      bgColor: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      showBadge: true,
    }
  if (points >= 40)
    return {
      grade: 3,
      status: "Зачет/Автомат",
      color: "text-green-600 dark:text-green-400",
      bgColor: "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200",
      showBadge: true,
    }
  return {
    grade: 2,
    status: "Неудовлетворительно",
    color: "text-red-600 dark:text-red-400",
    bgColor: "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200",
    showBadge: true,
  }
}

// Проверка на недопуск к экзамену для конкретной дисциплины
const hasExamDisqualification = (discipline: DisciplinesResponse["disciplines"][0]): boolean => {
  if (!discipline.score_data) return false
  const attendance = discipline.score_data.find(
    (score) => score.title === "Посещения" && score.now < 10
  )
  if (attendance === undefined) {
    return true;
  }
  return !!attendance
}

export function PerformanceDashboard({ onBack }: PerformanceDashboardProps) {
  const [disciplinesData, setDisciplinesData] = useState<DisciplinesResponse | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState("")
  const [expandedDisciplines, setExpandedDisciplines] = useState<Set<number>>(new Set())

  useEffect(() => {
    const loadDisciplines = async () => {
      try {
        const response = await apiClient.getDisciplines()
        setDisciplinesData(response.data)
      } catch (error) {
        setError("Не удалось загрузить данные об успеваемости")
      } finally {
        setIsLoading(false)
      }
    }

    loadDisciplines()
  }, [])

  if (isLoading) {
    return (
        <div className="min-h-screen bg-background flex items-center justify-center">
          <div className="text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4"></div>
            <p className="text-muted-foreground">Загрузка данных...</p>
          </div>
        </div>
    )
  }

  if (error) {
    return (
        <div className="min-h-screen bg-background">
          <StudentInfoHeader />
          <main className="container px-4 py-6">
            <div className="flex items-center mb-6">
              <Button variant="ghost" size="icon" onClick={onBack} className="mr-2">
                <ArrowLeft className="h-4 w-4" />
              </Button>
              <div className="flex items-center space-x-2">
                <GraduationCap className="h-6 w-6 text-primary" />
                <h1 className="text-lg font-semibold">Успеваемость</h1>
              </div>
            </div>
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          </main>
        </div>
    )
  }

  const disciplines = disciplinesData?.disciplines || []
  const totalStudents = disciplinesData?.count_students || 0
  const avgGrade = disciplines.length > 0 ? disciplines.reduce((sum, d) => sum + d.total, 0) / disciplines.length : 0
  const avgGroupGrade =
      disciplines.length > 0 ? disciplines.reduce((sum, d) => sum + d.avg_group, 0) / disciplines.length : 0

  const avgGradeInfo = getGradeInfo(avgGrade)

  return (
      <div className="min-h-screen bg-background">
        <StudentInfoHeader />

        <main className="container px-4 py-6 space-y-6">
          <div className="grid grid-cols-2 gap-3">
            <Card>
              <CardContent className="px-4 text-center">
                <Award className="h-6 w-6 text-primary mx-auto mb-1" />
                <div className="text-xl font-bold text-primary">{avgGrade.toFixed(1)}</div>
                <p className="text-xs text-muted-foreground mb-1">Твой средний балл</p>
              </CardContent>
            </Card>

            <Card>
              <CardContent className="px-4 text-center">
                <Target className="h-6 w-6 text-primary mx-auto mb-1" />
                <div className="text-xl font-bold text-primary">{avgGroupGrade.toFixed(1)}</div>
                <p className="text-xs text-muted-foreground mb-1">Средний балл группы</p>
              </CardContent>
            </Card>
          </div>

          <div className="space-y-3">
            <h2 className="text-xl font-semibold">Предметы</h2>
            {disciplines.map((discipline, index) => {
              const isDisqualified = hasExamDisqualification(discipline)
              const gradeInfo = getGradeInfo(discipline.total, isDisqualified)
              const isExpanded = expandedDisciplines.has(index)

              const toggleExpanded = (open: boolean) => {
                const newExpanded = new Set(expandedDisciplines)
                if (open) {
                  newExpanded.add(index)
                } else {
                  newExpanded.delete(index)
                }
                setExpandedDisciplines(newExpanded)
              }

              const hasDetails =
                (discipline.score_data && discipline.score_data.length > 0) ||
                discipline.avg_group >= 0

              return (
                <Collapsible key={index} open={isExpanded} onOpenChange={toggleExpanded}>
                  <Card className="py-2">
                    <CardContent className="px-3">
                      <CollapsibleTrigger asChild>
                        <div className="flex items-center justify-between mb-2 cursor-pointer">
                          <div className="flex-1 min-w-0">
                            <h3 className="font-semibold text-sm truncate">{discipline.title}</h3>
                            <div className="flex items-center gap-2 mt-1">
                              {gradeInfo.showBadge && (
                                <Badge className={`${gradeInfo.bgColor} text-xs`}>
                                  {gradeInfo.status}
                                </Badge>
                              )}
                              {isDisqualified && (
                                <Badge variant="destructive" className="flex items-center gap-1 text-xs">
                                  <AlertTriangle className="h-3 w-3" />
                                  Недопуск
                                </Badge>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-2 ml-2">
                            <div className="text-right">
                              <div className={`text-lg font-bold ${gradeInfo.color}`}>
                                {discipline.total.toFixed(1)}
                              </div>
                              <div className="text-xs text-muted-foreground">из 100</div>
                            </div>
                            {hasDetails && (
                              <div className="ml-1">
                                {isExpanded ? (
                                  <ChevronUp className="h-4 w-4 text-muted-foreground" />
                                ) : (
                                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                                )}
                              </div>
                            )}
                          </div>
                        </div>
                      </CollapsibleTrigger>

                      {hasDetails && (
                        <CollapsibleContent>
                          <div className="mt-3 pt-3 border-t space-y-2">
                            <div className="flex items-center justify-between text-sm pb-2 border-b">
                              <div className="flex gap-1">
                                <span className="text-muted-foreground">Общий балл:</span>
                                  <span className="font-medium">
                                    {discipline.total.toFixed(1)}
                                  </span>
                              </div>
                              <div className="flex items-center gap-3">
                                {discipline.avg_group >= 0 && (
                                  <span className="text-xs text-muted-foreground">
                                    (Средний по группе: {discipline.avg_group.toFixed(1)})
                                  </span>
                                )}
                              </div>
                            </div>
                            {discipline.score_data && discipline.score_data.map((score, scoreIndex) => {
                              const isLowAttendance = score.title === "Посещения" && score.now < 10
                              return (
                                <div 
                                  key={scoreIndex} 
                                  className={`flex items-center justify-between text-sm ${isLowAttendance ? "text-red-600 dark:text-red-400" : ""}`}
                                >
                                  <span className={isLowAttendance ? "font-semibold" : "text-muted-foreground"}>
                                    {score.title}:
                                  </span>
                                  <span className={`font-medium text-right ${isLowAttendance ? "text-red-600 dark:text-red-400" : ""}`}>
                                    {score.now.toFixed(1)} / {score.max.toFixed(1)}
                                    {isLowAttendance && (
                                      <span className="text-xs flex items-center gap-1">
                                        <AlertTriangle className="h-3 w-3" />
                                        Недопуск
                                      </span>
                                    )}
                                  </span>
                                </div>
                              )
                            })}
                          </div>
                        </CollapsibleContent>
                      )}
                    </CardContent>
                  </Card>
                </Collapsible>
              )
            })}
          </div>
        </main>
      </div>
  )
}
