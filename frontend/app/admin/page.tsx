"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { useAuth } from "@/hooks/use-auth"
import { Users, UserPlus, QrCode, GraduationCap, ScanLine, Activity} from "lucide-react"
import { useEffect, useState } from "react"
import { apiClient } from "@/lib/api"

interface AdminStats {
    total_users: number
    users_today: number
    total_qr_scans: number
    today_qr_scans: number
    unique_groups: number
    bot_unique_users: number
}

export default function AdminPage() {
    const { user, isLoading, isAuthenticated } = useAuth()
    const [stats, setStats] = useState<AdminStats | null>(null)
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState<string>("")

    useEffect(() => {
        let mounted = true
        setLoading(true)
        setError("")

        apiClient.getAdminStats()
            .then((res) => {
                if (!mounted) return
                setStats(res.data)
            })
            .catch((err) => {
                if (!mounted) return
                console.error("Failed to load admin stats:", err)
                setError("Ошибка загрузки статистики")
            })
            .finally(() => {
                if (!mounted) return
                setLoading(false)
            })

        return () => { mounted = false }
    }, [])

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
        return (
            <div className="min-h-screen bg-background flex items-center justify-center">
                <div className="text-center space-y-4">
                    <h1 className="text-2xl font-bold">Доступ запрещен</h1>
                    <p className="text-muted-foreground">Необходима авторизация</p>
                </div>
            </div>
        )
    }

    return (
        <div className="min-h-screen bg-background">
            <div className="container px-4 py-6 space-y-6">
                <div className="flex items-center justify-between">
                    <div>
                        <h1 className="text-3xl font-bold">Админ панель</h1>
                        <p className="text-muted-foreground">Статистика и управление системой</p>
                    </div>
                </div>

                {loading ? (
                    <div className="flex items-center justify-center p-8">
                        <LoadingSpinner size="lg" className="text-primary" />
                        <span className="ml-2 text-muted-foreground">Загрузка статистики...</span>
                    </div>
                ) : error ? (
                    <div className="p-4 rounded-lg bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800">
                        <p className="text-sm text-red-700 dark:text-red-300">{error}</p>
                    </div>
                ) : stats ? (
                    <>
                        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
                            <Card className="hover:shadow-lg transition-shadow">
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-sm font-medium">Всего пользователей</CardTitle>
                                    <Users className="h-4 w-4 text-muted-foreground" />
                                </CardHeader>
                                <CardContent>
                                    <div className="text-2xl font-bold">{stats.total_users}</div>
                                    <p className="text-xs text-muted-foreground">
                                        Зарегистрированных пользователей
                                    </p>
                                </CardContent>
                            </Card>

                            <Card className="hover:shadow-lg transition-shadow">
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-sm font-medium">Зарегистрировались сегодня</CardTitle>
                                    <UserPlus className="h-4 w-4 text-muted-foreground" />
                                </CardHeader>
                                <CardContent>
                                    <div className="text-2xl font-bold text-green-600 dark:text-green-400">{stats.users_today}</div>
                                    <p className="text-xs text-muted-foreground">
                                        Новых пользователей сегодня
                                    </p>
                                </CardContent>
                            </Card>

                            <Card className="hover:shadow-lg transition-shadow">
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-sm font-medium">Всего QR сканов</CardTitle>
                                    <QrCode className="h-4 w-4 text-muted-foreground" />
                                </CardHeader>
                                <CardContent>
                                    <div className="text-2xl font-bold">{stats.total_qr_scans}</div>
                                    <p className="text-xs text-muted-foreground">
                                        Всего сканирований QR кодов
                                    </p>
                                </CardContent>
                            </Card>

                            <Card className="hover:shadow-lg transition-shadow">
                                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                                    <CardTitle className="text-sm font-medium">QR сканов сегодня</CardTitle>
                                    <ScanLine className="h-4 w-4 text-muted-foreground" />
                                </CardHeader>
                                <CardContent>
                                    <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">{stats.today_qr_scans}</div>
                                    <p className="text-xs text-muted-foreground">
                                        Сканирований за сегодня
                                    </p>
                                </CardContent>
                            </Card>
                        </div>
   
                        <div className="grid gap-6 md:grid-cols-2">
                            <Card>
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2">
                                        <Activity className="h-5 w-5" />
                                        Активность
                                    </CardTitle>
                                    <CardDescription>Показатели активности пользователей</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium">Сканов на пользователя</span>
                                        <span className="text-sm text-muted-foreground">
                                            {stats.total_users > 0 ? (stats.total_qr_scans / stats.total_users).toFixed(1) : 0}
                                        </span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium">Сканов сегодня на пользователя</span>
                                        <span className="text-sm text-muted-foreground">
                                            {stats.total_users > 0 ? (stats.today_qr_scans / stats.total_users).toFixed(1) : 0}
                                        </span>
                                    </div>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2">
                                        <GraduationCap className="h-5 w-5" />
                                        Группы
                                    </CardTitle>
                                    <CardDescription>Статистика по группам</CardDescription>
                                </CardHeader>
                                <CardContent className="space-y-4">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium">Уникальных групп</span>
                                        <span className="text-sm font-medium text-purple-600 dark:text-purple-400">
                                            {stats.unique_groups}
                                        </span>
                                    </div>
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium">Пользователей в группе</span>
                                        <span className="text-sm text-muted-foreground">
                                            {stats.unique_groups > 0 ? (stats.total_users / stats.unique_groups).toFixed(1) : 0}
                                        </span>
                                    </div>
                                </CardContent>
                            </Card>
			    <Card className="col-span-full">
   			        <CardHeader>
       			            <CardTitle className="flex items-center gap-2">
           			        <Users className="h-5 w-5" />
           			        Заходы в бот
       				    </CardTitle>
       				    <CardDescription>Уникальные пользователи за сегодня</CardDescription>
   			        </CardHeader>
   			        <CardContent>
       			            <div className="text-2xl font-bold text-green-600 dark:text-green-400">
           			        {stats.bot_unique_users}
      				    </div>
       				    <p className="text-xs text-muted-foreground">
           			        разных людей заходило в бот
       				    </p>
   			        </CardContent>
			    </Card>
                        </div>
                    </>
                ) : null}
            </div>
        </div>
    )
}
