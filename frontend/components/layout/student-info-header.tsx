"use client"

import { useAuth } from "@/hooks/use-auth"
import { Card, CardContent } from "@/components/ui/card"
import { User, GraduationCap } from "lucide-react"

export function StudentInfoHeader() {
    const { user } = useAuth()

    if (!user) {
        return null
    }

    return (
        <div className="bg-card p-4">
            <div className="flex items-center gap-3">
                <div className="flex-shrink-0">
                    <div className="w-10 h-10 rounded-full bg-primary/10 flex items-center justify-center">
                        <User className="h-5 w-5 text-primary"/>
                    </div>
                </div>
                <div className="flex-1 min-w-0">
                    <h2 className="font-semibold text-lg truncate">{user.fullname}</h2>
                    <div className="flex items-center gap-1 text-sm text-muted-foreground">
                        <GraduationCap className="h-3 w-3"/>
                        <span>{user.group}</span>
                    </div>
                </div>
            </div>
        </div>
    )
}
