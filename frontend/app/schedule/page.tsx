"use client"

import { ScheduleView } from "@/components/schedule/schedule-view"
import { useRouter } from "next/navigation"

export default function SchedulePage() {
  const router = useRouter()

  return <ScheduleView onBack={() => router.back()} />
}
