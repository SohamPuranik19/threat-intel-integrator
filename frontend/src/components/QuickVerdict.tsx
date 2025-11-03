'use client'

import React from 'react'
import { CheckCircle, AlertCircle, AlertTriangle, Shield, Info } from 'lucide-react'

export default function QuickVerdict({ data }: any){
  if (!data) return null
  
  const score = data.threat_score ?? data.heuristic_score ?? 0
  const classification = data.classification || 'Unknown'
  
  let status = classification
  let statusColor = 'text-text-secondary'
  let bgColor = 'bg-gray-500/10'
  let borderColor = 'border-gray-500/20'
  let icon = <Info size={32} />
  
  if (status === 'Malicious' || score >= 75) {
    status = 'Malicious'
    statusColor = 'text-danger'
    bgColor = 'bg-danger/10'
    borderColor = 'border-danger/30'
    icon = <AlertCircle size={32} className="text-danger" />
  } else if (status === 'Suspicious' || score >= 40) {
    status = 'Suspicious'
    statusColor = 'text-warning'
    bgColor = 'bg-warning/10'
    borderColor = 'border-warning/30'
    icon = <AlertTriangle size={32} className="text-warning" />
  } else if (status === 'Benign') {
    statusColor = 'text-success'
    bgColor = 'bg-success/10'
    borderColor = 'border-success/30'
    icon = <CheckCircle size={32} className="text-success" />
  }

  return (
    <div className={`card border-2 ${borderColor} ${bgColor} animate-fadeIn`}>
      <div className="flex items-start gap-4">
        <div className={`p-4 rounded-xl ${bgColor} border ${borderColor}`}>
          {icon}
        </div>
        
        <div className="flex-1">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xs text-text-secondary uppercase tracking-wide mb-1">
                Quick Verdict
              </div>
              <div className="text-2xl font-bold text-light">
                {data.indicator || data.query || 'Result'}
              </div>
            </div>
            <div className="text-right">
              <div className="text-xs text-text-secondary uppercase tracking-wide mb-1">
                Threat Score
              </div>
              <div className={`text-3xl font-bold font-mono ${statusColor}`}>
                {score}
              </div>
            </div>
          </div>
          
          <div className="mt-3 flex items-center gap-3">
            <span className={`badge badge-${status.toLowerCase()} text-sm px-3 py-1`}>
              {status}
            </span>
            {data.category && (
              <span className="text-sm text-text-secondary">
                Category: <span className="text-primary font-semibold">{data.category}</span>
              </span>
            )}
            {data.confidence && (
              <span className="text-sm text-text-secondary">
                Confidence: <span className="text-primary font-semibold">{data.confidence}</span>
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Additional Details */}
      <div className="mt-4 pt-4 border-t border-primary/10">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          {data.country && (
            <div>
              <div className="text-text-secondary text-xs mb-1">Country</div>
              <div className="text-light font-semibold">{data.country}</div>
            </div>
          )}
          {data.isp && (
            <div>
              <div className="text-text-secondary text-xs mb-1">ISP</div>
              <div className="text-light font-semibold">{data.isp}</div>
            </div>
          )}
          {data.domain_resolves !== undefined && (
            <div>
              <div className="text-text-secondary text-xs mb-1">DNS Resolution</div>
              <div className="text-light font-semibold">
                {data.domain_resolves ? '✓ Resolves' : '✗ No DNS'}
              </div>
            </div>
          )}
          {data.mx !== undefined && (
            <div>
              <div className="text-text-secondary text-xs mb-1">MX Records</div>
              <div className="text-light font-semibold">
                {data.mx ? '✓ Found' : '✗ None'}
              </div>
            </div>
          )}
        </div>
      </div>

      {(data.summary || data.notes) && (
        <div className="mt-4 p-3 rounded-lg bg-black/20 border border-primary/10">
          <div className="text-sm text-text-secondary">
            {data.summary || data.notes}
          </div>
        </div>
      )}
    </div>
  )
}
