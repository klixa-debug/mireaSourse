"use client"

import { QrScanner } from "@/components/qr-scanner/qr-scanner"
import { useRouter } from "next/navigation"

export default function QrScannerPage() {
  const router = useRouter()

  return <QrScanner onBack={() => router.back()} />
}
