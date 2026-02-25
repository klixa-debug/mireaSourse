"use client"

import { SettingsPage } from "@/components/settings/settings-page"
import { useRouter } from "next/navigation"

export default function StudentsPage() {
  const router = useRouter()

  return <SettingsPage onBack={() => router.back()} />
}
