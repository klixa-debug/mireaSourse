"use client"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { StatusBadge } from "@/components/ui/status-badge"
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { SignUpForm } from "@/components/auth/sign-up-form"
import { useAuth } from "@/hooks/use-auth"
import { useUniversityStatus } from "@/hooks/use-university-status"
import { useTodaySchedule } from "@/hooks/use-today-schedule"
import { Calendar, Clock, FileText, MapPin, User, AlertTriangle, Shield } from "lucide-react"
import Link from "next/link"
import {StudentInfoHeader} from "@/components/layout/student-info-header";
import { useEffect, useMemo, useState } from "react"
import { apiClient, type Deadline } from "@/lib/api"
import { TotpSetup } from "@/components/auth/totp-setup"

export default function HomePage() {
    const { user, isLoading, isAuthenticated, refreshUser } = useAuth()
    const [showTotpSetup, setShowTotpSetup] = useState(false)
    const { 
        status, 
        isLoading: statusLoading, 
        getStatusText, 
        getStatusColor, 
        getTimeInfo, 
        formatEventTime, 
        getEventDescription, 
        getEventsCount,
        getEventsText
    } = useUniversityStatus()
    const { 
        lessons, 
        isLoading: scheduleLoading, 
        error: scheduleError, 
        formatTime, 
        getLessonTypeColor, 
        getLessonTypeText,
        getCurrentLesson,
        getNextLesson,
        getUpcomingLessons
    } = useTodaySchedule()

    const [deadlines, setDeadlines] = useState<Deadline[]>([])
    const [deadlinesLoading, setDeadlinesLoading] = useState<boolean>(true)
    const [deadlinesError, setDeadlinesError] = useState<string>("")
    const [showEventDetails, setShowEventDetails] = useState<boolean>(false)

    useEffect(() => {
        // let mounted = true
        // setDeadlinesLoading(true)
        // setDeadlinesError("")
        // apiClient.getDeadlines()
        //     .then((res) => {
        //         if (!mounted) return
        //         const sorted = [...res.data].sort((a, b) => a.timestamp - b.timestamp)
        //         setDeadlines(sorted)
        //     })
        //     .catch(() => {
        //         if (!mounted) return
        //         setDeadlinesError("Ошибка загрузки дедлайнов")
        //     })
        //     .finally(() => {
        //         if (!mounted) return
        //         setDeadlinesLoading(false)
        //     })
        // return () => { mounted = false }
    }, [])

    const [showAllDeadlines, setShowAllDeadlines] = useState<boolean>(false)
    const visibleDeadlines = useMemo(() => showAllDeadlines ? deadlines : deadlines.slice(0, 3), [showAllDeadlines, deadlines])

    function getDeadlineBadge(deadline: Deadline): { label: string; status: "success" | "warning" | "error" } {
        const nowSec = Math.floor(Date.now() / 1000)
        const diffSec = deadline.timestamp - nowSec
        const diffDays = Math.floor(diffSec / 86400)
        const diffHours = Math.floor((diffSec % 86400) / 3600)

        if (diffSec <= 0) {
            return { label: "Просрочено", status: "error" }
        }
        if (diffDays === 0) {
            return { label: `${diffHours} ч`, status: "warning" }
        }
        if (diffDays <= 3) {
            return { label: `${diffDays} дн`, status: "warning" }
        }
        return { label: `${diffDays} дн`, status: "success" }
    }

    if (isLoading) {
        return (
            <div className="min-h-screen bg-background flex items-center justify-center">
                <div className="text-center space-y-4">
                    <LoadingSpinner size="lg" className="mx-auto text-primary" />
                    <p className="text-muted-foreground">Загрузка приложения...</p>
                </div>
            </div>
        )
    }

    if (!isAuthenticated) {
        return <SignUpForm />
    }

    if (showTotpSetup) {
        return <TotpSetup onComplete={async () => { await refreshUser(); setShowTotpSetup(false) }} onBack={() => setShowTotpSetup(false)} />
    }

    return (
        <div className="min-h-screen bg-background">
            <StudentInfoHeader/>

            <main className="container px-4 py-6 space-y-6">
                {user && !user.has_totp_secret && (
                    <Alert variant="destructive" className="bg-gradient-to-r from-yellow-50 to-yellow-100 dark:from-yellow-950 dark:to-yellow-900 border-yellow-200 dark:border-yellow-800 text-yellow-900 dark:text-yellow-100">
                        <Shield className="h-5 w-5 text-yellow-600 dark:text-yellow-400" />
                        <AlertTitle className="text-yellow-900 dark:text-yellow-100">
                            Настройка двухфакторной авторизации
                        </AlertTitle>
                        <AlertDescription className="text-yellow-800 dark:text-yellow-200 mt-1">
                            Если у вас уже включена двухфакторная авторизация, настройте ее в боте.
                            <Button
                                onClick={() => setShowTotpSetup(true)}
                                variant="outline"
                                size="sm"
                                className="ml-2 mt-2"
                            >
                                Настроить
                            </Button>
                        </AlertDescription>
                    </Alert>
                )}

                <Alert variant="destructive" className="bg-gradient-to-r from-orange-50 to-orange-100 dark:from-orange-950 dark:to-orange-900 border-orange-200 dark:border-orange-800 text-orange-900 dark:text-orange-100">
                    <AlertTriangle className="h-5 w-5 text-orange-600 dark:text-orange-400" />
                    <AlertTitle className="text-orange-900 dark:text-orange-100">
                        Важная информация
                    </AlertTitle>
                    <AlertDescription className="text-orange-800 dark:text-orange-200 mt-1">
                        Бот работает нестабильно. Пожалуйста, следите за новостями в канале.
                        <Link 
                            href="https://t.me/mirea_tools" 
                            target="_blank" 
                            rel="noopener noreferrer"
                            className="underline font-medium hover:text-orange-900 dark:hover:text-orange-100 transition-colors"
                        >
                            @mirea_tools
                        </Link>
                    </AlertDescription>
                </Alert>

                <Card>
                    <CardHeader>
                        <CardTitle className="text-lg flex items-center gap-2">
                            <MapPin className="h-5 w-5" />
                            Статус в вузе
                        </CardTitle>
                        <CardDescription>Информация о нахождении в университете</CardDescription>
                    </CardHeader>
                    <CardContent>
                        {statusLoading ? (
                            <div className="flex items-center justify-center p-4">
                                <LoadingSpinner size="sm" className="text-primary" />
                                <span className="ml-2 text-muted-foreground">Загрузка статуса...</span>
                            </div>
                        ) : (
                            <div className="space-y-4">
                                <div 
                                    className={`flex items-center justify-between p-4 rounded-lg border ${
                                        getStatusColor() === 'success'
                                            ? 'bg-gradient-to-r from-green-50 to-green-100 dark:from-green-950 dark:to-green-900 border-green-200 dark:border-green-800'
                                            : getStatusColor() === 'warning'
                                                ? 'bg-gradient-to-r from-orange-50 to-orange-100 dark:from-orange-950 dark:to-orange-900 border-orange-200 dark:border-orange-800'
                                                : 'bg-gradient-to-r from-red-50 to-red-100 dark:from-red-950 dark:to-red-900 border-red-200 dark:border-red-800'
                                    }`}
                                >
                                    <div className="space-y-1">
                                        <h4 className={`font-medium ${
                                            getStatusColor() === 'success'
                                                ? 'text-green-900 dark:text-green-100'
                                                : getStatusColor() === 'warning'
                                                    ? 'text-orange-900 dark:text-orange-100'
                                                    : 'text-red-900 dark:text-red-100'
                                        }`}>
                                            Пропуск проверяется
                                        </h4>
                                        {getTimeInfo() && (
                                            <p className={`text-sm ${
                                                getStatusColor() === 'success'
                                                    ? 'text-green-700 dark:text-green-300'
                                                    : getStatusColor() === 'warning'
                                                        ? 'text-orange-700 dark:text-orange-300'
                                                        : 'text-red-700 dark:text-red-300'
                                            }`}>
                                                {getTimeInfo()}
                                            </p>
                                        )}
                                        {getEventsCount() > 0 && (
                                            <div 
                                                className="flex items-center gap-1 cursor-pointer hover:opacity-80 transition-opacity"
                                                onClick={() => setShowEventDetails(!showEventDetails)}
                                            >
                                                <p className={`text-xs ${
                                                    getStatusColor() === 'success'
                                                        ? 'text-green-600 dark:text-green-400'
                                                        : getStatusColor() === 'warning'
                                                            ? 'text-orange-600 dark:text-orange-400'
                                                            : 'text-red-600 dark:text-red-400'
                                                }`}>
                                                    {getEventsText()}
                                                </p>
                                                <div
                                                    className={`transition-transform duration-200 ${
                                                        showEventDetails ? 'rotate-90' : 'rotate-0'
                                                    }`}
                                                >
                                                    <svg 
                                                        width="12" 
                                                        height="12" 
                                                        viewBox="0 0 24 24" 
                                                        fill="none" 
                                                        stroke="currentColor" 
                                                        strokeWidth="2" 
                                                        strokeLinecap="round" 
                                                        strokeLinejoin="round"
                                                        className={`${
                                                            getStatusColor() === 'success'
                                                                ? 'text-green-600 dark:text-green-400'
                                                                : getStatusColor() === 'warning'
                                                                    ? 'text-orange-600 dark:text-orange-400'
                                                                    : 'text-red-600 dark:text-red-400'
                                                        }`}
                                                    >
                                                        <polyline points="9,18 15,12 9,6"></polyline>
                                                    </svg>
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <StatusBadge status={getStatusColor()}>
                                            {getStatusText()}
                                        </StatusBadge>
                                    </div>
                                </div>

                                {/* Детальная информация о событиях */}
                                {showEventDetails && status?.events && status.events.length > 0 && (
                                    <div className="space-y-2">
                                        <h5 className="text-sm font-medium text-muted-foreground">Детали проходов:</h5>
                                        <div className="space-y-2">
                                            {status.events.map((event, index) => (
                                                <div 
                                                    key={index}
                                                    className="flex items-center justify-between p-3 bg-muted/50 rounded-lg border"
                                                >
                                                    <div className="flex items-center gap-3">
                                                        <div className={`w-2 h-2 rounded-full ${
                                                            event.is_entry ? 'bg-green-500' : 'bg-red-500'
                                                        }`} />
                                                        <div>
                                                            <p className="text-sm font-medium">
                                                                {event.is_entry ? 'Вход' : 'Выход'}
                                                            </p>
                                                            <p className="text-xs text-muted-foreground">
                                                                {event.is_entry ? event.entry_location : event.exit_location}
                                                            </p>
                                                        </div>
                                                    </div>
                                                    <div className="text-right">
                                                        <p className="text-sm font-mono">
                                                            {formatEventTime(event.time)}
                                                        </p>
                                                    </div>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                    </CardContent>
                </Card>

                {/* Deadlines Block */}
                {/*<Card>*/}
                {/*    <CardHeader>*/}
                {/*        <div className="flex items-center justify-between">*/}
                {/*            <div>*/}
                {/*                <CardTitle className="text-lg flex items-center gap-2">*/}
                {/*                    <FileText className="h-5 w-5" />*/}
                {/*                    Дедлайны*/}
                {/*                </CardTitle>*/}
                {/*                <CardDescription>Сроки сдачи работ и заданий</CardDescription>*/}
                {/*            </div>*/}
                {/*        </div>*/}
                {/*    </CardHeader>*/}
                {/*    <CardContent className="space-y-3">*/}
                {/*        {deadlinesLoading ? (*/}
                {/*            <div className="flex items-center justify-center p-4">*/}
                {/*                <LoadingSpinner size="sm" className="text-primary" />*/}
                {/*                <span className="ml-2 text-muted-foreground">Загрузка дедлайнов...</span>*/}
                {/*            </div>*/}
                {/*        ) : deadlinesError ? (*/}
                {/*            <div className="p-4 rounded-lg bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800">*/}
                {/*                <p className="text-sm text-red-700 dark:text-red-300">{deadlinesError}</p>*/}
                {/*            </div>*/}
                {/*        ) : visibleDeadlines.length === 0 ? (*/}
                {/*            <div className="p-4 rounded-lg bg-muted/50 text-center">*/}
                {/*                <FileText className="h-8 w-8 text-muted-foreground mx-auto mb-2" />*/}
                {/*                <p className="text-sm text-muted-foreground">Нет предстоящих дедлайнов</p>*/}
                {/*            </div>*/}
                {/*        ) : (*/}
                {/*            <>*/}
                {/*            {visibleDeadlines.map((d) => {*/}
                {/*                const badge = getDeadlineBadge(d)*/}
                {/*                return (*/}
                {/*                    <div*/}
                {/*                        key={`${d.subject}-${d.timestamp}-${d.title}`}*/}
                {/*                        className={`flex items-center justify-between p-4 rounded-lg border ${*/}
                {/*                            badge.status === 'error'*/}
                {/*                                ? 'bg-gradient-to-r from-red-50 to-red-100 dark:from-red-950 dark:to-red-900 border-red-200 dark:border-red-800'*/}
                {/*                                : badge.status === 'warning'*/}
                {/*                                ? 'bg-gradient-to-r from-orange-50 to-orange-100 dark:from-orange-950 dark:to-orange-900 border-orange-200 dark:border-orange-800'*/}
                {/*                                : 'bg-gradient-to-r from-green-50 to-green-100 dark:from-green-950 dark:to-green-900 border-green-200 dark:border-green-800'*/}
                {/*                        }`}*/}
                {/*                    >*/}
                {/*                        <div className="space-y-1 min-w-0">*/}
                {/*                            <h4 className={`font-medium ${*/}
                {/*                                badge.status === 'error'*/}
                {/*                                    ? 'text-red-900 dark:text-red-100'*/}
                {/*                                    : badge.status === 'warning'*/}
                {/*                                    ? 'text-orange-900 dark:text-orange-100'*/}
                {/*                                    : 'text-green-900 dark:text-green-100'*/}
                {/*                            } truncate`}>{d.title}</h4>*/}
                {/*                            <p className={`text-sm truncate ${*/}
                {/*                                badge.status === 'error'*/}
                {/*                                    ? 'text-red-700 dark:text-red-300'*/}
                {/*                                    : badge.status === 'warning'*/}
                {/*                                    ? 'text-orange-700 dark:text-orange-300'*/}
                {/*                                    : 'text-green-700 dark:text-green-300'*/}
                {/*                            }`}>*/}
                {/*                                {d.subject}*/}
                {/*                            </p>*/}
                {/*                        </div>*/}
                {/*                        <StatusBadge status={badge.status}>{badge.label}</StatusBadge>*/}
                {/*                    </div>*/}
                {/*                )*/}
                {/*            })}*/}
                {/*            {deadlines.length > 3 && (*/}
                {/*                <div className="flex justify-center pt-1">*/}
                {/*                    <Button variant="ghost" size="sm" onClick={() => setShowAllDeadlines(v => !v)}>*/}
                {/*                        {showAllDeadlines ? 'Свернуть' : 'Показать все'}*/}
                {/*                    </Button>*/}
                {/*                </div>*/}
                {/*            )}*/}
                {/*            </>*/}
                {/*        )}*/}
                {/*    </CardContent>*/}
                {/*</Card>*/}
            </main>
        </div>
    )
}
