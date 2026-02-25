"use client"

import { useEffect } from "react"
import { Card, CardContent } from "@/components/ui/card"
import Image from "next/image"

export function MaintenancePage() {
  useEffect(() => {
    const handlePopState = (e: PopStateEvent) => {
      window.history.pushState(null, "", window.location.href)
    }

    window.history.pushState(null, "", window.location.href)
    window.addEventListener("popstate", handlePopState)

    return () => {
      window.removeEventListener("popstate", handlePopState)
    }
  }, [])

  return (
    <div className="min-h-screen bg-background flex items-center justify-center p-4 fixed inset-0 z-[9999] bg-background/95 backdrop-blur-sm">
      <Card className="w-full max-w-md">
        <CardContent className="pt-6 pb-6">
          <div className="text-center space-y-4">
            <h1 className="text-2xl font-bold">Технические работы</h1>
            <p className="text-muted-foreground">
              Разработчик думает о новых фичах или исправляет баги
            </p>
            <div className="flex justify-center pt-4">
              <img
                src="/utka.gif"
                alt="Технические работы"
                width={200}
                height={200}
                className="rounded-lg"
              />
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}

