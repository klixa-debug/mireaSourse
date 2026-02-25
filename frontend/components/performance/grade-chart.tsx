"use client"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import type { Discipline } from "@/lib/api"
import { Bar, BarChart, ResponsiveContainer, XAxis, YAxis, CartesianGrid, Tooltip, Legend } from "recharts"

interface GradeChartProps {
  disciplines: Discipline[]
  title?: string
  description?: string
}

export function GradeChart({ disciplines, title = "Успеваемость по предметам", description }: GradeChartProps) {
  const chartData = disciplines.map((discipline) => ({
    name: discipline.title.length > 12 ? discipline.title.substring(0, 12) + "..." : discipline.title,
    fullName: discipline.title,
    "Ваш балл": discipline.total,
    "Средний по группе": discipline.avg_group,
  }))

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      const data = chartData.find((item) => item.name === label)
      return (
        <div className="bg-background border rounded-lg p-3 shadow-lg">
          <p className="font-medium mb-2">{data?.fullName}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} className="text-sm" style={{ color: entry.color }}>
              {entry.name}: {entry.value.toFixed(1)}
            </p>
          ))}
        </div>
      )
    }
    return null
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={chartData} margin={{ top: 20, right: 30, left: 20, bottom: 60 }}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis
                dataKey="name"
                angle={-45}
                textAnchor="end"
                height={80}
                fontSize={12}
                interval={0}
                className="fill-muted-foreground"
              />
              <YAxis className="fill-muted-foreground" />
              <Tooltip content={<CustomTooltip />} />
              <Legend />
              <Bar dataKey="Ваш балл" fill="hsl(var(--primary))" radius={[2, 2, 0, 0]} />
              <Bar dataKey="Средний по группе" fill="hsl(var(--muted-foreground))" radius={[2, 2, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  )
}
