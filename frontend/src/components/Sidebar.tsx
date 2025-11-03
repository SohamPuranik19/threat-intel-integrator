'use client'

import React from 'react'
import { Filter, Shield } from 'lucide-react'

export default function Sidebar() {
  return (
    <div className="bg-gradient-to-br from-gray-900 to-black border border-orange-500/20 rounded-2xl shadow-2xl shadow-orange-500/10 overflow-hidden">
      {/* Top accent */}
      <div className="h-1 bg-gradient-to-r from-transparent via-orange-500 to-transparent"></div>
      
      <div className="p-6 space-y-6">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-orange-500/10 rounded-lg">
            <Filter size={20} className="text-orange-500" />
          </div>
          <div>
            <h4 className="text-lg font-bold text-white">Filters</h4>
            <p className="text-xs text-gray-500">(Backend integration pending)</p>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Classification</label>
          <select className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all">
            <option>Any</option>
            <option>Benign</option>
            <option>Suspicious</option>
            <option>Malicious</option>
          </select>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-2">Category</label>
          <select className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 text-white focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all">
            <option>Any</option>
            <option>Malware</option>
            <option>Phishing</option>
            <option>Spam</option>
          </select>
        </div>

        <div className="pt-4">
          <button className="w-full bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white py-3 rounded-lg font-semibold transition-all shadow-lg shadow-orange-500/30 hover:shadow-orange-500/50">
            Apply Filters
          </button>
        </div>
      </div>
    </div>
  )
}
