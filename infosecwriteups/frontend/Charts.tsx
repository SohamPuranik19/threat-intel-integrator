'use client'

import React from 'react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'

export default function Charts({ data }: any) {
  if (!data || data.length === 0) return null

  const buckets = [0,20,40,60,80,100].map((upper, idx, arr) => {
    const lower = idx === 0 ? 0 : arr[idx-1]
    return {
      range: `${lower}-${upper}`,
      count: data.filter((d: any) => {
        const s = d.threat_score ?? d.score ?? 0
        return s >= lower && s < upper
      }).length
    }
  })

  return (
    <div className="card">
      <h3 className="text-lg font-bold mb-4">Threat Score Distribution</h3>
      <div style={{ width: '100%', height: 240 }}>
        <ResponsiveContainer>
          <BarChart data={buckets}>
            <CartesianGrid strokeDasharray="3 3" stroke="#071025" />
            <XAxis dataKey="range" stroke="#7f9bb3" />
            <YAxis stroke="#7f9bb3" />
            <Tooltip />
            <Bar dataKey="count" fill="#00d9ff" />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
