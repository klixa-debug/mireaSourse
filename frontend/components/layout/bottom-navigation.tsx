"use client"

import { usePathname } from "next/navigation"
import Link from "next/link"
import { QrCode, Calendar, GraduationCap, Settings, User, Shield, MessageSquare } from "lucide-react"
import { cn } from "@/lib/utils"
import { useAdmin } from "@/hooks/use-admin"

const getNavItems = (isAdmin: boolean) => [
  {
    href: "/qr-scanner/",
    icon: QrCode,
    label: "QR-сканер",
  },
  {
    href: "/schedule/",
    icon: Calendar,
    label: "Расписание",
  },
  {
    href: "/",
    icon: User,
    label: "Главная",
  },
  {
    href: "/performance/",
    icon: GraduationCap,
    label: "Баллы",
  },
  {
    href: "/reviews/",
    icon: MessageSquare,
    label: "Отзывы",
  },
  {
    href: "/students/",
    icon: Settings,
    label: "Настройки",
  },
  ...(isAdmin ? [{
    href: "/admin/",
    icon: Shield,
    label: "Админ",
  }] : []),
]

export function BottomNavigation() {
  const pathname = usePathname()
  const { isAdmin } = useAdmin()
  const navItems = getNavItems(isAdmin)

  return (
      <nav className="fixed bottom-0 left-0 right-0 z-50 bg-background/95 backdrop-blur supports-[backdrop-filter]:bg-background/60 border-t pb-safe">
        <div className="container px-4">
          <div className={`grid py-2 ${isAdmin ? 'grid-cols-7' : 'grid-cols-6'}`}>
            {navItems.map((item) => {
              const Icon = item.icon
              const isActive = pathname === item.href

              return (
                  <Link
                      key={item.href}
                      href={item.href}
                      className={cn(
                          "flex flex-col items-center gap-1 p-2 rounded-lg transition-colors min-w-0",
                          isActive
                              ? "text-primary-foreground bg-primary"
                              : "text-muted-foreground hover:text-foreground hover:bg-accent",
                      )}
                  >
                    <Icon className="h-5 w-5" />
                    <span className="text-xs font-medium truncate">{item.label}</span>
                  </Link>
              )
            })}
          </div>
        </div>
      </nav>
  )
}
