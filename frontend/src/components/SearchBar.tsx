'use client'

import React, { useState } from 'react'
import axios from 'axios'

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
      const res = await axios.post('http://127.0.0.1:8000/lookup', { 
        indicator: q, 
        analyze: true 
      })
      onResult?.(res.data)
      setSuccess(`✓ Analysis complete for "${q}"`)
      setTimeout(() => setSuccess(null), 3000)
    } catch (err: any){
      const errorMsg = err?.response?.data?.detail || err?.message || 'Lookup failed'
      setError(`⚠️ ${errorMsg}`)
    } finally { 
      setLoading(false) 
    }
  }

  async function fetchAll(){
    setLoadingTable(true)
    setError(null)
    setSuccess(null)
    
    try{
      const res = await axios.get('http://127.0.0.1:8000/search?limit=200')
      onFetchAll?.(res.data.items || [])
      setSuccess(`✓ Loaded ${res.data.items?.length || 0} records`)
      setTimeout(() => setSuccess(null), 3000)
    }catch(err: any){ 
      const errorMsg = err?.response?.data?.detail || err?.message || 'Failed to load data'
      setError(`⚠️ ${errorMsg}`)
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
    <div className="space-y-3">
      <form className="card flex flex-col gap-3" onSubmit={handleSearch}>
        <div className="flex gap-3">
          <input 
            value={q} 
            onChange={(e)=>setQ(e.target.value)} 
            placeholder="Enter IP address or domain (e.g., 8.8.8.8 or google.com)" 
            className="flex-1 bg-transparent border border-primary/20 rounded-md px-3 py-2 focus:border-primary/50 focus:outline-none transition-colors"
            disabled={loading || loadingTable}
          />
          <button 
            type="submit" 
            className="btn-primary min-w-[120px] disabled:opacity-50 disabled:cursor-not-allowed hover:bg-primary/90 transition-colors" 
            disabled={loading || loadingTable}
          >
            {loading ? '⏳ Analyzing...' : '🔍 Lookup'}
          </button>
          <button 
            type="button" 
            className="btn-primary min-w-[120px] disabled:opacity-50 disabled:cursor-not-allowed hover:bg-primary/90 transition-colors" 
            onClick={fetchAll}
            disabled={loading || loadingTable}
          >
            {loadingTable ? '⏳ Loading...' : '📊 Load Table'}
          </button>
        </div>

        {/* Sample Searches */}
        <div className="flex items-center gap-2 text-sm">
          <span className="text-text-secondary">Quick searches:</span>
          {SAMPLE_SEARCHES.map((sample, idx) => (
            <button
              key={idx}
              type="button"
              onClick={() => quickSearch(sample.value)}
              className="px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
              disabled={loading || loadingTable}
            >
              {sample.label}
            </button>
          ))}
        </div>

        {/* Status Messages */}
        {error && (
          <div className="text-danger text-sm bg-danger/10 border border-danger/20 rounded-md px-3 py-2">
            {error}
          </div>
        )}
        {success && (
          <div className="text-success text-sm bg-success/10 border border-success/20 rounded-md px-3 py-2">
            {success}
          </div>
        )}
      </form>
    </div>
  )
}
