"use client"

import { useEffect, useRef } from "react"

interface Snowflake {
  x: number
  y: number
  size: number
  speed: number
  opacity: number
  drift: number
}

export function SnowEffect() {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const animationFrameRef = useRef<number>()
  const snowflakesRef = useRef<Snowflake[]>([])

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return

    // Используем 2d контекст с оптимизациями для iOS
    const ctx = canvas.getContext("2d", { 
      alpha: true,
      desynchronized: true, // Для лучшей производительности на мобильных
    })
    if (!ctx) return

    // Определение устройства iOS
    const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || 
      (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1)

    // Установка размера canvas с учетом DPR для четкости на Retina дисплеях
    const resizeCanvas = () => {
      const dpr = window.devicePixelRatio || 1
      const width = window.innerWidth
      const height = window.innerHeight

      canvas.width = width * dpr
      canvas.height = height * dpr
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`

      // Масштабирование контекста для Retina
      ctx.scale(dpr, dpr)
    }

    resizeCanvas()
    
    // Debounce для resize на iOS
    let resizeTimeout: ReturnType<typeof setTimeout>
    const handleResize = () => {
      clearTimeout(resizeTimeout)
      resizeTimeout = setTimeout(resizeCanvas, 100)
    }
    window.addEventListener("resize", handleResize, { passive: true })

    // Создание снежинки
    const createSnowflake = (): Snowflake => ({
      x: Math.random() * window.innerWidth,
      y: -10,
      size: Math.random() * 3 + 1,
      speed: Math.random() * 2 + 0.5,
      opacity: Math.random() * 0.5 + 0.3,
      drift: Math.random() * 0.5 - 0.25,
    })

    // Инициализация снежинок (меньше на iOS для лучшей производительности)
    const baseCount = Math.floor((window.innerWidth * window.innerHeight) / 15000)
    const snowflakeCount = isIOS ? Math.min(baseCount, 50) : baseCount
    snowflakesRef.current = Array.from({ length: snowflakeCount }, createSnowflake)

    // Анимация
    const animate = (currentTime: number) => {
      // Очистка canvas
      ctx.clearRect(0, 0, window.innerWidth, window.innerHeight)

      snowflakesRef.current.forEach((flake) => {
        // Обновление позиции
        flake.y += flake.speed
        flake.x += flake.drift

        // Сброс снежинки, если она упала
        if (flake.y > window.innerHeight) {
          flake.y = -10
          flake.x = Math.random() * window.innerWidth
        }

        // Обработка горизонтального выхода за границы
        if (flake.x < 0) {
          flake.x = window.innerWidth
        } else if (flake.x > window.innerWidth) {
          flake.x = 0
        }

        // Рисование снежинки с оптимизацией для iOS
        ctx.beginPath()
        ctx.arc(flake.x, flake.y, flake.size, 0, Math.PI * 2)
        ctx.fillStyle = `rgba(255, 255, 255, ${flake.opacity})`
        ctx.fill()
      })

      animationFrameRef.current = requestAnimationFrame(animate)
    }

    // Запуск анимации
    animationFrameRef.current = requestAnimationFrame(animate)

    // Остановка анимации при скрытии страницы (экономия батареи)
    const handleVisibilityChange = () => {
      if (document.hidden) {
        if (animationFrameRef.current) {
          cancelAnimationFrame(animationFrameRef.current)
          animationFrameRef.current = undefined
        }
      } else {
        if (!animationFrameRef.current) {
          animationFrameRef.current = requestAnimationFrame(animate)
        }
      }
    }
    document.addEventListener("visibilitychange", handleVisibilityChange)

    return () => {
      window.removeEventListener("resize", handleResize)
      document.removeEventListener("visibilitychange", handleVisibilityChange)
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current)
      }
      clearTimeout(resizeTimeout)
    }
  }, [])

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 pointer-events-none z-[9999]"
      style={{
        willChange: "transform",
        transform: "translate3d(0, 0, 0)",
        WebkitTransform: "translate3d(0, 0, 0)",
        backfaceVisibility: "hidden",
        WebkitBackfaceVisibility: "hidden",
        WebkitPerspective: 1000,
        perspective: 1000,
        isolation: "isolate",
      }}
    />
  )
}

