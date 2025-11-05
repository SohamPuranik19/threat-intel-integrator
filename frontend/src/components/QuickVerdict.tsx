'use client'

import React from 'react'
import { CheckCircle, AlertCircle, AlertTriangle, Shield, Info } from 'lucide-react'

export default function QuickVerdict({ data }: any){
  if (!data) return null
  
  // Extract data from enhanced API response
  const scorecard = data.scorecard || {}
  const classification = data.classification || {}
  const relatedIocs = data.related_iocs || {}
  
  const score = scorecard.composite_score || data.threat_score || data.heuristic_score || 0
  const status = scorecard.classification || data.classification || 'Unknown'
  const severity = scorecard.severity || 'Unknown'
  const iocType = classification.ioc_type || 'unknown'
  const confidence = classification.confidence || 0
  const mitreTactic = classification.mitre_tactic || ''
  const mitreTechnique = classification.mitre_technique || ''
  
  let statusColor = 'text-gray-400'
  let bgColor = 'bg-gray-500/10'
  let borderColor = 'border-gray-500/20'
  let icon = <Info size={32} className="text-gray-400" />
  
  if (status === 'Malicious' || score >= 70) {
    statusColor = 'text-red-500'
    bgColor = 'bg-red-500/10'
    borderColor = 'border-red-500/30'
    icon = <AlertCircle size={32} className="text-red-500" />
  } else if (status === 'Suspicious' || score >= 40) {
    statusColor = 'text-orange-500'
    bgColor = 'bg-orange-500/10'
    borderColor = 'border-orange-500/30'
    icon = <AlertTriangle size={32} className="text-orange-500" />
  } else if (status === 'Benign') {
    statusColor = 'text-green-500'
    bgColor = 'bg-green-500/10'
    borderColor = 'border-green-500/30'
    icon = <CheckCircle size={32} className="text-green-500" />
  }

  return (
    <div className={`bg-gradient-to-br from-gray-900 to-black rounded-2xl shadow-2xl shadow-orange-500/10 overflow-hidden border-2 ${borderColor} ${bgColor}`}>
      <div className="h-1 bg-gradient-to-r from-transparent via-orange-500 to-transparent animate-glow"></div>
      
      <div className="p-6">
        <div className="flex items-start gap-4">
          <div className={`p-4 rounded-xl ${bgColor} border ${borderColor}`}>
            {icon}
          </div>
          
          <div className="flex-1">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-gray-400 uppercase tracking-wide mb-1">
                  Quick Verdict
                </div>
                <div className="text-2xl font-bold text-white">
                  {data.indicator || data.query || 'Result'}
                </div>
              </div>
              <div className="text-right">
                <div className="text-xs text-gray-400 uppercase tracking-wide mb-1">
                  Threat Score
                </div>
                <div className={`text-3xl font-bold font-mono ${statusColor}`}>
                  {score}
                </div>
              </div>
            </div>
            
            <div className="mt-3 flex items-center gap-3 flex-wrap">
              <span className={`px-3 py-1 rounded-lg text-sm font-semibold border ${
                status === 'Malicious' ? 'bg-red-500/20 text-red-400 border-red-500/50' :
                status === 'Suspicious' ? 'bg-orange-500/20 text-orange-400 border-orange-500/50' :
                status === 'Benign' ? 'bg-green-500/20 text-green-400 border-green-500/50' :
                'bg-gray-500/20 text-gray-400 border-gray-500/50'
              }`}>
                {status}
              </span>
              {severity && severity !== 'Unknown' && (
                <span className="px-3 py-1 rounded-lg text-sm font-semibold bg-purple-500/20 text-purple-400 border border-purple-500/50">
                  {severity} Severity
                </span>
              )}
              {iocType && iocType !== 'unknown' && iocType !== 'benign' && (
                <span className="text-sm text-gray-400">
                  IOC Type: <span className="text-orange-400 font-semibold">{iocType.toUpperCase()}</span>
                </span>
              )}
              {confidence > 0 && (
                <span className="text-sm text-gray-400">
                  Confidence: <span className="text-orange-400 font-semibold">{confidence}%</span>
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Additional Details */}
        <div className="mt-4 pt-4 border-t border-orange-500/10">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            {scorecard.sources_checked && (
              <div>
                <div className="text-gray-400 text-xs mb-1">Sources Checked</div>
                <div className="text-white font-semibold">
                  {scorecard.sources_checked}/{scorecard.total_sources || 9}
                </div>
              </div>
            )}
            {mitreTactic && mitreTactic !== 'None' && (
              <div>
                <div className="text-gray-400 text-xs mb-1">MITRE Tactic</div>
                <div className="text-white font-semibold text-xs">{mitreTactic}</div>
              </div>
            )}
            {mitreTechnique && mitreTechnique !== 'None' && (
              <div>
                <div className="text-gray-400 text-xs mb-1">MITRE Technique</div>
                <div className="text-white font-semibold">{mitreTechnique}</div>
              </div>
            )}
            {(relatedIocs.domains?.length || relatedIocs.ips?.length || 0) > 0 && (
              <div>
                <div className="text-gray-400 text-xs mb-1">Related IOCs</div>
                <div className="text-white font-semibold">
                  {(relatedIocs.domains?.length || 0) + (relatedIocs.ips?.length || 0)} found
                </div>
              </div>
            )}
            {data.country && (
              <div>
                <div className="text-gray-400 text-xs mb-1">Country</div>
                <div className="text-white font-semibold">{data.country}</div>
              </div>
            )}
            {data.isp && (
              <div>
                <div className="text-gray-400 text-xs mb-1">ISP</div>
                <div className="text-white font-semibold">{data.isp}</div>
              </div>
            )}
            {data.domain_resolves !== undefined && (
              <div>
                <div className="text-gray-400 text-xs mb-1">DNS Resolution</div>
                <div className="text-white font-semibold">
                  {data.domain_resolves ? '✓ Resolves' : '✗ No DNS'}
                </div>
              </div>
            )}
            {data.mx !== undefined && (
              <div>
                <div className="text-gray-400 text-xs mb-1">MX Records</div>
                <div className="text-white font-semibold">
                  {data.mx ? '✓ Found' : '✗ None'}
                </div>
              </div>
            )}
          </div>
        </div>

        {(data.summary || data.notes) && (
          <div className="mt-4 p-3 rounded-lg bg-black/20 border border-orange-500/10">
            <div className="text-sm text-gray-400">
              {data.summary || data.notes}
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        @keyframes glow {
          0%, 100% {
            opacity: 0.5;
          }
          50% {
            opacity: 1;
          }
        }

        .animate-glow {
          animation: glow 3s ease-in-out infinite;
        }
      `}</style>
    </div>
  )
}
