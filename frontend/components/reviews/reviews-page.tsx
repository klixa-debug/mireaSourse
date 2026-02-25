"use client"

import { useState, useMemo, useCallback } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { Badge } from "@/components/ui/badge"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
} from "@/components/ui/dialog"
import { StudentInfoHeader } from "@/components/layout/student-info-header"
import { LoadingSpinner } from "@/components/ui/loading-spinner"
import { useReviews } from "@/hooks/use-reviews"
import type { Teacher, Review } from "@/lib/api"
import {
    Search,
    MessageSquare,
    ArrowLeft,
    Plus,
    Trash2,
    UserRound,
    GraduationCap,
    Send,
    AlertCircle,
} from "lucide-react"

function getCourseLabel(course: number): string {
    if (course <= 0) return "Студент"
    const lastDigit = course % 10
    if (lastDigit === 1 && course !== 11) return `${course} курс`
    if (lastDigit >= 2 && lastDigit <= 4 && (course < 12 || course > 14)) return `${course} курс`
    return `${course} курс`
}

function formatDate(timestamp: number): string {
    const date = new Date(timestamp)
    return date.toLocaleDateString("ru-RU", {
        day: "numeric",
        month: "short",
        year: "numeric",
    })
}

export function ReviewsPage() {
    const {
        allTeachers,
        isLoadingTeachers,
        teacherReviews,
        isLoadingReviews,
        isSubmitting,
        error,
        clearError,
        addTeacher,
        loadReviews,
        createReview,
        deleteReview,
        resetTeacher,
        loadAllTeachers,
    } = useReviews()

    const [query, setQuery] = useState("")
    const [selectedTeacher, setSelectedTeacher] = useState<Teacher | null>(null)
    const [comment, setComment] = useState("")
    const [isAddDialogOpen, setIsAddDialogOpen] = useState(false)
    const [newTeacherName, setNewTeacherName] = useState("")
    const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false)

    // Локальная фильтрация по запросу
    const filteredTeachers = useMemo(() => {
        const q = query.trim().toLowerCase()
        if (q.length < 2) return allTeachers
        return allTeachers.filter((t) => t.name.toLowerCase().includes(q))
    }, [allTeachers, query])

    const handleSelectTeacher = useCallback(
        (teacher: Teacher) => {
            setSelectedTeacher(teacher)
            loadReviews(teacher.id)
        },
        [loadReviews],
    )

    const handleBack = useCallback(() => {
        setSelectedTeacher(null)
        setComment("")
        resetTeacher()
    }, [resetTeacher])

    const handleSubmitReview = useCallback(async () => {
        if (!selectedTeacher || !comment.trim()) return
        const ok = await createReview(selectedTeacher.id, comment.trim())
        if (ok) setComment("")
    }, [selectedTeacher, comment, createReview])

    const handleDeleteReview = useCallback(async () => {
        if (!selectedTeacher) return
        const ok = await deleteReview(selectedTeacher.id)
        if (ok) setIsDeleteDialogOpen(false)
    }, [selectedTeacher, deleteReview])

    const handleAddTeacher = useCallback(async () => {
        if (!newTeacherName.trim()) return
        const teacher = await addTeacher(newTeacherName)
        if (teacher) {
            setIsAddDialogOpen(false)
            setNewTeacherName("")
            loadAllTeachers()
            handleSelectTeacher(teacher)
        }
    }, [newTeacherName, addTeacher, handleSelectTeacher, loadAllTeachers])

    const myReview = teacherReviews?.reviews.find((r) => r.is_mine)
    const hasMyReview = !!myReview

    // Экран отзывов конкретного преподавателя
    if (selectedTeacher) {
        return (
            <div className="min-h-screen bg-background">
                <StudentInfoHeader />

                <main className="container px-4 py-6 space-y-4 pb-32">
                    <Button variant="ghost" size="sm" onClick={handleBack} className="gap-2 -ml-2">
                        <ArrowLeft className="h-4 w-4" />
                        Назад к списку
                    </Button>

                    <Card>
                        <CardHeader>
                            <CardTitle className="text-[16px] flex items-center gap-2">
                                {selectedTeacher.name}
                            </CardTitle>
                            <CardDescription>
                                {teacherReviews
                                    ? `${teacherReviews.reviews.length} ${getReviewWord(teacherReviews.reviews.length)}`
                                    : "Загрузка..."}
                            </CardDescription>
                        </CardHeader>
                    </Card>

                    {error && (
                        <Alert variant="destructive">
                            <AlertCircle className="h-4 w-4" />
                            <AlertDescription>{error}</AlertDescription>
                        </Alert>
                    )}

                    {/* Форма отзыва */}
                    {!hasMyReview && (
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-base">Оставить отзыв</CardTitle>
                                <CardDescription>Анонимно, максимум 255 символов</CardDescription>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                <Textarea
                                    placeholder="Напишите ваш отзыв о преподавателе..."
                                    value={comment}
                                    onChange={(e) => setComment(e.target.value.slice(0, 255))}
                                    rows={3}
                                    className="resize-none"
                                />
                                <div className="flex items-center justify-between">
                                    <span className="text-xs text-muted-foreground">
                                        {comment.length}/255
                                    </span>
                                    <Button
                                        onClick={handleSubmitReview}
                                        disabled={isSubmitting || !comment.trim()}
                                        size="sm"
                                    >
                                        {isSubmitting ? (
                                            <LoadingSpinner size="sm" className="mr-2" />
                                        ) : (
                                            <Send className="h-4 w-4 mr-2" />
                                        )}
                                        Отправить
                                    </Button>
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {/* Список отзывов */}
                    {isLoadingReviews ? (
                        <div className="flex items-center justify-center p-8">
                            <LoadingSpinner size="lg" className="text-primary" />
                        </div>
                    ) : teacherReviews && teacherReviews.reviews.length === 0 ? (
                        <Card>
                            <CardContent className="p-8 text-center">
                                <MessageSquare className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                                <h4 className="text-lg font-semibold mb-2">Пока нет отзывов</h4>
                                <p className="text-muted-foreground">
                                    Будьте первым, кто оставит отзыв на этого преподавателя
                                </p>
                            </CardContent>
                        </Card>
                    ) : (
                        <div className="space-y-3">
                            {teacherReviews?.reviews.map((review) => (
                                <ReviewCard
                                    key={review.id}
                                    review={review}
                                    onDelete={() => setIsDeleteDialogOpen(true)}
                                />
                            ))}
                        </div>
                    )}

                    {/* Диалог подтверждения удаления */}
                    <Dialog open={isDeleteDialogOpen} onOpenChange={setIsDeleteDialogOpen}>
                        <DialogContent className="max-w-sm">
                            <DialogHeader>
                                <DialogTitle>Удалить отзыв?</DialogTitle>
                                <DialogDescription>
                                    Это действие нельзя отменить. Вы сможете оставить новый отзыв.
                                </DialogDescription>
                            </DialogHeader>
                            <div className="flex gap-2 justify-end">
                                <Button variant="outline" onClick={() => setIsDeleteDialogOpen(false)}>
                                    Отмена
                                </Button>
                                <Button
                                    variant="destructive"
                                    onClick={handleDeleteReview}
                                    disabled={isSubmitting}
                                >
                                    {isSubmitting ? (
                                        <LoadingSpinner size="sm" className="mr-2" />
                                    ) : (
                                        <Trash2 className="h-4 w-4 mr-2" />
                                    )}
                                    Удалить
                                </Button>
                            </div>
                        </DialogContent>
                    </Dialog>
                </main>
            </div>
        )
    }

    // Экран поиска преподавателей
    return (
        <div className="min-h-screen bg-background">
            <StudentInfoHeader />

            <main className="container px-4 py-6 space-y-4 pb-32">
                <Card>
                    <CardHeader>
                        <CardTitle className="text-lg flex items-center gap-2">
                            <MessageSquare className="h-5 w-5" />
                            Отзывы на преподавателей
                        </CardTitle>
                        <CardDescription>
                            Найдите преподавателя и прочитайте или оставьте анонимный отзыв
                        </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-4">
                        <div className="relative">
                            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                            <Input
                                placeholder="Введите ФИО преподавателя..."
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                className="pl-10"
                            />
                        </div>

                            {error && (
                            <Alert variant="destructive">
                                <AlertCircle className="h-4 w-4" />
                                <AlertDescription>{error}</AlertDescription>
                            </Alert>
                        )}
                    </CardContent>
                </Card>

                {/* Список преподавателей */}
                {isLoadingTeachers ? (
                    <div className="flex items-center justify-center p-8">
                        <LoadingSpinner size="lg" className="text-primary" />
                    </div>
                ) : filteredTeachers.length > 0 ? (
                    <div className="space-y-2">
                        {filteredTeachers.map((teacher) => (
                            <Card
                                key={teacher.id}
                                className="cursor-pointer hover:bg-accent/50 transition-colors py-0"
                                onClick={() => handleSelectTeacher(teacher)}
                            >
                                <CardContent className="p-4">
                                    <div className="flex items-center justify-between">
                                        <div className="flex items-center gap-3">
                                            <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center flex-shrink-0">
                                                <GraduationCap className="h-5 w-5 text-primary" />
                                            </div>
                                            <div className="min-w-0">
                                                <h4 className="font-medium truncate">
                                                    {teacher.name}
                                                </h4>
                                                <p className="text-sm text-muted-foreground">
                                                    {teacher.review_count}{" "}
                                                    {getReviewWord(teacher.review_count)}
                                                </p>
                                            </div>
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>
                        ))}
                    </div>
                ) : query.trim().length >= 2 ? (
                    <Card>
                        <CardContent className="p-6 text-center space-y-4">
                            <Search className="h-10 w-10 text-muted-foreground mx-auto" />
                            <div>
                                <h4 className="font-semibold mb-1">Преподаватель не найден</h4>
                                <p className="text-sm text-muted-foreground">
                                    Вы можете добавить преподавателя самостоятельно
                                </p>
                            </div>
                            <Button onClick={() => {
                                setNewTeacherName(query.trim())
                                setIsAddDialogOpen(true)
                            }}>
                                <Plus className="h-4 w-4 mr-2" />
                                Добавить преподавателя
                            </Button>
                        </CardContent>
                    </Card>
                ) : (
                    <Card>
                        <CardContent className="p-8 text-center">
                            <GraduationCap className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                            <h4 className="text-lg font-semibold mb-2">Нет преподавателей</h4>
                            <p className="text-muted-foreground text-sm">
                                Преподаватели пока не добавлены
                            </p>
                        </CardContent>
                    </Card>
                )}

                {/* Диалог добавления преподавателя */}
                <Dialog open={isAddDialogOpen} onOpenChange={setIsAddDialogOpen}>
                    <DialogContent className="max-w-md">
                        <DialogHeader>
                            <DialogTitle>Добавить преподавателя</DialogTitle>
                            <DialogDescription>
                                Укажите полное ФИО преподавателя
                            </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4">
                            <Input
                                placeholder="Иванов Иван Иванович"
                                value={newTeacherName}
                                onChange={(e) => setNewTeacherName(e.target.value)}
                            />
                            <div className="flex gap-2 justify-end">
                                <Button variant="outline" onClick={() => setIsAddDialogOpen(false)}>
                                    Отмена
                                </Button>
                                <Button onClick={handleAddTeacher} disabled={!newTeacherName.trim()}>
                                    <Plus className="h-4 w-4 mr-2" />
                                    Добавить
                                </Button>
                            </div>
                        </div>
                    </DialogContent>
                </Dialog>
            </main>
        </div>
    )
}

// --- Вспомогательные компоненты ---

function ReviewCard({ review, onDelete }: { review: Review; onDelete: () => void }) {
    return (
        <Card className={review.is_mine ? "border-primary/40 py-2" : "py-2"}>
            <CardContent className="px-4 py-0 space-y-2">
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                        <div className="w-7 h-7 rounded-full bg-muted flex items-center justify-center">
                            <UserRound className="h-4 w-4 text-muted-foreground" />
                        </div>
                        <Badge variant="secondary" className="text-xs">
                            {getCourseLabel(review.course)}
                        </Badge>
                        {review.is_mine && (
                            <Badge variant="outline" className="text-xs">
                                Вы
                            </Badge>
                        )}
                    </div>
                    <div className="flex items-center gap-2">
                        <span className="text-xs text-muted-foreground">
                            {formatDate(review.created_at)}
                        </span>
                        {review.is_mine && (
                            <Button
                                variant="ghost"
                                size="sm"
                                onClick={onDelete}
                                className="h-7 w-7 p-0 text-destructive hover:text-destructive"
                            >
                                <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                        )}
                    </div>
                </div>
                <p className="text-sm leading-relaxed">{review.comment}</p>
            </CardContent>
        </Card>
    )
}

function getReviewWord(count: number): string {
    const lastDigit = count % 10
    const lastTwo = count % 100
    if (lastTwo >= 11 && lastTwo <= 19) return "отзывов"
    if (lastDigit === 1) return "отзыв"
    if (lastDigit >= 2 && lastDigit <= 4) return "отзыва"
    return "отзывов"
}
