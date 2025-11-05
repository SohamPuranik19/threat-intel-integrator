'use client'

import React, { useState } from 'react'
import axios from 'axios'
import { Search, Database, Zap } from 'lucide-react'

const SAMPLE_SEARCHES = [
  { label: 'Google DNS', value: '8.8.8.8' },
  { label: 'Google.com', value: 'google.com' },
  { label: 'Malicious Example', value: 'malware-domain.evil.com' },
]

export default function SearchBar({ onResult, onFetchAll }: any){
  const [q, setQ] = useState('')
  const [loading, setLoading] = useState(false)
  const [loadingTable, setLoadingTable] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)

  async function handleSearch(e?: any){
    if (e) e.preventDefault()
    if (!q) {
      setError('Please enter an IP address or domain')
      return
    }
    
    setLoading(true)
    setError(null)
    setSuccess(null)
    
    try {
      // Auto-detect indicator type
      let indicator_type = 'domain'
      
      // Check if it's an IP address
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/
      if (ipRegex.test(q)) {
        indicator_type = 'ip'
      }
      // Check if it's a URL
      else if (q.startsWith('http://') || q.startsWith('https://')) {
        indicator_type = 'url'
      }
      // Check if it's a hash (MD5: 32, SHA1: 40, SHA256: 64 hex chars)
      else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(q)) {
        indicator_type = 'hash'
      }
      
      const res = await axios.post('http://127.0.0.1:8000/analyze', { 
        indicator: q,
        indicator_type: indicator_type
      })
      
      // Extract the data from the new API response format
      if (res.data.status === 'success') {
        onResult?.(res.data.data)
        setSuccess(`✓ Analysis complete for "${q}" (${indicator_type})`)
      } else {
        setError(res.data.message || 'Analysis failed')
      }
      
      setTimeout(() => setSuccess(null), 3000)
    } catch (err: any){
      const errorMsg = err?.response?.data?.detail || err?.message || 'Analysis failed'
      setError(errorMsg)
    } finally { 
      setLoading(false) 
    }
  }

  async function fetchAll(){
    setLoadingTable(true)
    setError(null)
    setSuccess(null)
    
    try{
      const res = await axios.get('http://127.0.0.1:8000/indicators?limit=200')
      const indicators = res.data.results || res.data.indicators || []
      onFetchAll?.(indicators)
      setSuccess(`✓ Loaded ${indicators.length} records`)
      setTimeout(() => setSuccess(null), 3000)
    }catch(err: any){ 
      const errorMsg = err?.response?.data?.detail || err?.message || 'Failed to load data'
      setError(errorMsg)
    } finally {
      setLoadingTable(false)
    }
  }

  function quickSearch(value: string) {
    setQ(value)
    setError(null)
    setSuccess(null)
  }

  return (
    <div className="bg-gradient-to-br from-gray-900 to-black border border-orange-500/20 rounded-2xl shadow-2xl shadow-orange-500/10 overflow-hidden">
      <div className="h-1 bg-gradient-to-r from-transparent via-orange-500 to-transparent animate-glow"></div>
      
      <form className="p-6 space-y-4" onSubmit={handleSearch}>
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input 
              value={q} 
              onChange={(e)=>setQ(e.target.value)} 
              placeholder="Enter IP address or domain (e.g., 8.8.8.8 or google.com)" 
              className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 pl-11 text-white placeholder-gray-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all"
              disabled={loading || loadingTable}
            />
            <Search size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          </div>
          <button 
            type="submit" 
            className="bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white px-6 py-3 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-orange-500/30 hover:shadow-orange-500/50 flex items-center gap-2" 
            disabled={loading || loadingTable}
          >
            {loading ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                Analyzing...
              </>
            ) : (
              <>
                <Zap size={18} />
                Lookup
              </>
            )}
          </button>
          <button 
            type="button" 
            className="bg-gray-800 hover:bg-gray-700 text-white px-6 py-3 rounded-lg font-semibold border border-orange-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-all flex items-center gap-2" 
            onClick={fetchAll}
            disabled={loading || loadingTable}
          >
            {loadingTable ? (
              <>
                <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                Loading...
              </>
            ) : (
              <>
                <Database size={18} />
                Load Table
              </>
            )}
          </button>
        </div>

        {/* Sample Searches */}
        <div className="flex items-center gap-2 text-sm">
          <span className="text-gray-400">Quick searches:</span>
          {SAMPLE_SEARCHES.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => quickSearch(sample.value)}
              className="px-3 py-1.5 rounded-lg bg-orange-500/10 text-orange-400 hover:bg-orange-500/20 border border-orange-500/30 transition-all"
              disabled={loading || loadingTable}
            >
              {sample.label}
            </button>
          ))}
        </div>

        {/* Status Messages */}
        {error && (
          <div className="text-red-400 text-sm bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3">
            ⚠️ {error}
          </div>
        )}
        {success && (
          <div className="text-orange-400 text-sm bg-orange-500/10 border border-orange-500/30 rounded-lg px-4 py-3">
            ✓ {success}
          </div>
        )}
      </form>

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
