import type React from "react"
import type { Metadata } from "next"
import { GeistSans } from "geist/font/sans"
import { GeistMono } from "geist/font/mono"
import { Analytics } from "@vercel/analytics/next"
import { ThemeProvider } from "@/components/theme-provider"
import { AuthProvider } from "@/hooks/use-auth"
import { Suspense } from "react"
import { RouteGuard } from "@/components/route-guard"
import { ErrorBoundary } from "@/components/error-boundary"
import { Snowflakes } from "@/components/christmas/snowflakes"
import "./globals.css"

export const metadata: Metadata = {
  title: "MIREA QR Bot",
  description: "Telegram Mini App для студентов МИРЭА - отметка посещаемости, расписание, успеваемость",
  viewport: "width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no",
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#1a1a1a" },
  ],
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="ru" suppressHydrationWarning>
    <body className={`font-sans ${GeistSans.variable} ${GeistMono.variable} antialiased`}>
    <ErrorBoundary>
      <Suspense fallback={null}>
        <ThemeProvider attribute="class" defaultTheme="system" enableSystem disableTransitionOnChange>
          <AuthProvider>
            <RouteGuard>
              {children}
            </RouteGuard>
          </AuthProvider>
        </ThemeProvider>
      </Suspense>
    </ErrorBoundary>
    <Analytics/>
    <script src="https://telegram.org/js/telegram-web-app.js"></script>
    </body>
    </html>
  )
}
