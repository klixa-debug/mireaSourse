"use client"

import { PerformanceDashboard } from "@/components/performance/performance-dashboard"
import { useRouter } from "next/navigation"

export default function PerformancePage() {
  const router = useRouter()

  return <PerformanceDashboard onBack={() => router.back()} />
}
