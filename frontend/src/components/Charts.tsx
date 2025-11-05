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
    <div className="bg-gradient-to-br from-gray-900 to-black rounded-2xl shadow-2xl shadow-orange-500/10 overflow-hidden border border-orange-500/20">
      <div className="h-1 bg-gradient-to-r from-transparent via-orange-500 to-transparent animate-glow" />
      <div className="p-6">
        <h3 className="text-lg font-bold mb-4 text-white">Threat Score Distribution</h3>
        <div style={{ width: '100%', height: 240 }}>
          <ResponsiveContainer>
            <BarChart data={buckets}>
              <CartesianGrid strokeDasharray="3 3" stroke="#0b1220" />
              <XAxis dataKey="range" stroke="#94a3b8" tick={{ fill: '#94a3b8' }} />
              <YAxis stroke="#94a3b8" tick={{ fill: '#94a3b8' }} />
              <Tooltip contentStyle={{ backgroundColor: '#071021', borderColor: '#1f2937', color: '#fff' }} labelStyle={{ color: '#9ca3af' }} />
              <Bar dataKey="count" fill="#f97316" radius={[6,6,0,0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <style jsx>{`
        @keyframes glow {
          0%, 100% { opacity: 0.5; }
          50% { opacity: 1; }
        }
        .animate-glow { animation: glow 3s ease-in-out infinite; }
      `}</style>
    </div>
  )
}
