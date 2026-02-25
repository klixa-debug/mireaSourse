"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent } from "@/components/ui/card"
import { Alert, AlertDescription } from "@/components/ui/alert"
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog"
import { apiClient, type Student } from "@/lib/api"
import { UserPlus, Search, Mail, User, GraduationCap } from "lucide-react"

interface AddStudentDialogProps {
  onStudentAdded: () => void
  trigger?: React.ReactNode
}

export function AddStudentDialog({ onStudentAdded, trigger }: AddStudentDialogProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [searchEmail, setSearchEmail] = useState("")
  const [foundStudent, setFoundStudent] = useState<Student | null>(null)
  const [isSearching, setIsSearching] = useState(false)
  const [isConnecting, setIsConnecting] = useState(false)
  const [error, setError] = useState("")

  const searchStudent = async () => {
    if (!searchEmail.trim()) return

    setIsSearching(true)
    setFoundStudent(null)
    setError("")

    try {
      const response = await apiClient.findStudent(searchEmail.trim())
      setFoundStudent(response.data)
    } catch (error) {
      setError("Студент не найден или произошла ошибка поиска")
    } finally {
      setIsSearching(false)
    }
  }

  const connectStudent = async () => {
    if (!foundStudent) return

    setIsConnecting(true)
    try {
      await apiClient.connectStudent(foundStudent.email)
      setIsOpen(false)
      setSearchEmail("")
      setFoundStudent(null)
      setError("")
      onStudentAdded()
    } catch (error) {
      setError("Не удалось добавить студента. Возможно, он уже подключен.")
    } finally {
      setIsConnecting(false)
    }
  }

  const handleOpenChange = (open: boolean) => {
    setIsOpen(open)
    if (!open) {
      setSearchEmail("")
      setFoundStudent(null)
      setError("")
    }
  }

  return (
    <Dialog open={isOpen} onOpenChange={handleOpenChange}>
      <DialogTrigger asChild>
        {trigger || (
          <Button className="w-full">
            <UserPlus className="mr-2 h-4 w-4" />
            Добавить студента
          </Button>
        )}
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Добавить студента</DialogTitle>
          <DialogDescription>Найдите студента по email адресу и добавьте его в свой список</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label htmlFor="search-email">Email студента</Label>
            <div className="flex gap-2">
              <Input
                id="search-email"
                type="email"
                placeholder="student@mirea.ru"
                value={searchEmail}
                onChange={(e) => setSearchEmail(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && searchStudent()}
              />
              <Button onClick={searchStudent} disabled={isSearching || !searchEmail.trim()}>
                {isSearching ? (
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current"></div>
                ) : (
                  <Search className="h-4 w-4" />
                )}
              </Button>
            </div>
          </div>

          {foundStudent && (
            <Card>
              <CardContent className="p-4">
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <User className="h-4 w-4 text-muted-foreground" />
                    <h4 className="font-semibold">{foundStudent.fullname}</h4>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <GraduationCap className="h-3 w-3" />
                    <span>{foundStudent.group}</span>
                  </div>
                  <div className="flex items-center gap-2 text-sm text-muted-foreground">
                    <Mail className="h-3 w-3" />
                    <span>{foundStudent.email}</span>
                  </div>
                  <Button onClick={connectStudent} disabled={isConnecting} className="w-full">
                    {isConnecting ? (
                      <>
                        <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-current mr-2"></div>
                        Добавление...
                      </>
                    ) : (
                      "Добавить студента"
                    )}
                  </Button>
                </div>
              </CardContent>
            </Card>
          )}

          {error && (
            <Alert variant="destructive">
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
