"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Alert, AlertDescription } from "@/components/ui/alert"
import { apiClient } from "@/lib/api"
import { Eye, EyeOff, CheckCircle } from "lucide-react"

export function ChangePasswordForm() {
    const [newPassword, setNewPassword] = useState("")
    const [showPassword, setShowPassword] = useState(false)
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState("")
    const [success, setSuccess] = useState("")

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault()
        setError("")
        setSuccess("")

        // Валидация
        if (!newPassword) {
            setError("Поле пароля обязательно для заполнения")
            return
        }

        setIsLoading(true)

        try {
            await apiClient.changePassword({
                new_password: newPassword,
            })

            setSuccess("Пароль успешно изменен")
            setNewPassword("")
        } catch (error: any) {
            setError("Проверьте пароль от ЛК")
        } finally {
            setIsLoading(false)
        }
    }

    const handleReset = () => {
        setError("")
        setSuccess("")
        setNewPassword("")
    }

    return (
        <div className="space-y-4">
            <form onSubmit={handleSubmit} className="space-y-4">
                <div className="space-y-2">
                    <Label htmlFor="new-password">Новый пароль</Label>
                    <div className="relative">
                        <Input
                            id="new-password"
                            type={showPassword ? "text" : "password"}
                            placeholder="Введите новый пароль"
                            value={newPassword}
                            onChange={(e) => setNewPassword(e.target.value)}
                            disabled={isLoading}
                        />
                        <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            className="absolute right-0 top-0 h-full px-3 py-2 hover:bg-transparent"
                            onClick={() => setShowPassword(!showPassword)}
                            disabled={isLoading}
                        >
                            {showPassword ? (
                                <EyeOff className="h-4 w-4" />
                            ) : (
                                <Eye className="h-4 w-4" />
                            )}
                        </Button>
                    </div>
                </div>

                {error && (
                    <Alert variant="destructive">
                        <AlertDescription>{error}</AlertDescription>
                    </Alert>
                )}

                {success && (
                    <Alert>
                        <CheckCircle className="h-4 w-4" />
                        <AlertDescription>{success}</AlertDescription>
                    </Alert>
                )}

                <div className="flex gap-2">
                    <Button
                        type="submit"
                        className="flex-1"
                        disabled={isLoading}
                    >
                        {isLoading ? "Сохранение..." : "Изменить пароль"}
                    </Button>
                </div>
            </form>
        </div>
    )
}
