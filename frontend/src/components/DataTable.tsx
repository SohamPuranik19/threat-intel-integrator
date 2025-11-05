'use client'

import React, { useState, useMemo } from 'react'
import { Download, Filter, ArrowUpDown, ArrowUp, ArrowDown } from 'lucide-react'

export default function DataTable({ data }: any) {
  const [filter, setFilter] = useState('')
  const [classificationFilter, setClassificationFilter] = useState('All')
  const [sortBy, setSortBy] = useState<string | null>(null)
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc')

  // Filter and sort data - must be called before any early returns
  const filteredAndSortedData = useMemo(() => {
    if (!data || data.length === 0) return []
    
    let filtered = data.filter((item: any) => {
      const matchesText = filter === '' || 
        item.indicator?.toLowerCase().includes(filter.toLowerCase()) ||
        item.indicator_type?.toLowerCase().includes(filter.toLowerCase()) ||
        item.ioc_type?.toLowerCase().includes(filter.toLowerCase())
      
      const matchesClassification = classificationFilter === 'All' || 
        item.classification === classificationFilter
      
      return matchesText && matchesClassification
    })

    if (sortBy) {
      filtered = [...filtered].sort((a, b) => {
        // Handle composite_score field name
        const sortField = sortBy === 'threat_score' ? 'composite_score' : sortBy
        let aVal = a[sortField]
        let bVal = b[sortField]
        
        if (typeof aVal === 'string') aVal = aVal.toLowerCase()
        if (typeof bVal === 'string') bVal = bVal.toLowerCase()
        
        if (aVal < bVal) return sortOrder === 'asc' ? -1 : 1
        if (aVal > bVal) return sortOrder === 'asc' ? 1 : -1
        return 0
      })
    }

    return filtered
  }, [data, filter, classificationFilter, sortBy, sortOrder])

  // Early return after hooks
  if (!data || data.length === 0) return (
    <div className="card text-center py-12">
      <p className="text-text-secondary">No data available. Click "Load Table" to view all indicators.</p>
    </div>
  )

  // Export to CSV
  function exportToCSV() {
    const headers = ['Indicator', 'Type', 'Classification', 'Score', 'IOC Type', 'Severity', 'Timestamp']
    const rows = filteredAndSortedData.map((item: any) => [
      item.indicator || '',
      item.indicator_type || '',
      item.classification || '',
      item.composite_score ?? item.threat_score ?? '',
      item.ioc_type || '',
      item.severity || '',
      item.created_at || item.timestamp || ''
    ])
    
    const csvContent = [
      headers.join(','),
      ...rows.map((row: any) => row.map((cell: any) => `"${cell}"`).join(','))
    ].join('\n')
    
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const link = document.createElement('a')
    const url = URL.createObjectURL(blob)
    link.setAttribute('href', url)
    link.setAttribute('download', `threat-intel-${new Date().toISOString().split('T')[0]}.csv`)
    link.style.visibility = 'hidden'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  function handleSort(column: string) {
    if (sortBy === column) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(column)
      setSortOrder('desc')
    }
  }

  function getSortIcon(column: string) {
    if (sortBy !== column) return <ArrowUpDown size={14} className="opacity-50" />
    return sortOrder === 'asc' ? <ArrowUp size={14} /> : <ArrowDown size={14} />
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-bold">Threat Intelligence Data</h3>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Filter size={16} className="text-text-secondary" />
            <select 
              value={classificationFilter}
              onChange={(e) => setClassificationFilter(e.target.value)}
              className="bg-transparent border border-primary/20 rounded-md px-3 py-1 text-sm focus:border-primary/50 focus:outline-none"
            >
              <option value="All">All Classifications</option>
              <option value="Benign">Benign</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Malicious">Malicious</option>
            </select>
          </div>
          <input
            type="text"
            placeholder="Filter by indicator..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-transparent border border-primary/20 rounded-md px-3 py-1 text-sm w-48 focus:border-primary/50 focus:outline-none"
          />
          <button 
            onClick={exportToCSV}
            className="flex items-center gap-2 px-3 py-1 bg-primary/10 text-primary rounded-md hover:bg-primary/20 transition-colors text-sm"
          >
            <Download size={16} />
            Export CSV
          </button>
        </div>
      </div>

      <div className="text-xs text-text-secondary mb-3">
        Showing {filteredAndSortedData.length} of {data.length} records
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left text-text-secondary border-b border-primary/10">
              <th className="p-2 cursor-pointer hover:text-primary transition-colors" onClick={() => handleSort('indicator')}>
                <div className="flex items-center gap-1">
                  Indicator {getSortIcon('indicator')}
                </div>
              </th>
              <th className="p-2 cursor-pointer hover:text-primary transition-colors" onClick={() => handleSort('indicator_type')}>
                <div className="flex items-center gap-1">
                  Type {getSortIcon('indicator_type')}
                </div>
              </th>
              <th className="p-2 cursor-pointer hover:text-primary transition-colors" onClick={() => handleSort('classification')}>
                <div className="flex items-center gap-1">
                  Classification {getSortIcon('classification')}
                </div>
              </th>
              <th className="p-2 cursor-pointer hover:text-primary transition-colors" onClick={() => handleSort('threat_score')}>
                <div className="flex items-center gap-1">
                  Score {getSortIcon('threat_score')}
                </div>
              </th>
              <th className="p-2">IOC Type</th>
              <th className="p-2">Severity</th>
              <th className="p-2 cursor-pointer hover:text-primary transition-colors" onClick={() => handleSort('created_at')}>
                <div className="flex items-center gap-1">
                  Timestamp {getSortIcon('created_at')}
                </div>
              </th>
            </tr>
          </thead>
          <tbody>
            {filteredAndSortedData.slice(0, 100).map((item: any, i: number) => (
              <tr key={i} className="border-t border-primary/6 hover:bg-primary/5 transition-colors">
                <td className="p-2 font-mono text-primary">{item.indicator}</td>
                <td className="p-2 text-text-secondary uppercase text-xs">{item.indicator_type || '-'}</td>
                <td className="p-2">
                  <span className={`badge ${
                    item.classification === 'Malicious' ? 'badge-malicious' : 
                    item.classification === 'Suspicious' ? 'badge-suspicious' : 
                    'badge-benign'
                  }`}>
                    {item.classification || 'Unknown'}
                  </span>
                </td>
                <td className="p-2 font-mono font-bold">{item.composite_score ?? item.threat_score ?? '-'}</td>
                <td className="p-2 text-text-secondary">
                  {item.ioc_type && item.ioc_type !== 'unknown' && item.ioc_type !== 'benign' ? (
                    <span className="text-orange-400 text-xs uppercase">{item.ioc_type}</span>
                  ) : '-'}
                </td>
                <td className="p-2 text-text-secondary text-xs">
                  {item.severity && item.severity !== 'Unknown' ? item.severity : '-'}
                </td>
                <td className="p-2 text-text-secondary text-xs">
                  {item.created_at?.substring(0, 19) || item.timestamp?.substring(0, 19) || '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filteredAndSortedData.length > 100 && (
        <div className="mt-4 text-center text-xs text-text-secondary">
          Showing first 100 of {filteredAndSortedData.length} filtered results
        </div>
      )}
    </div>
  )
}
