'use client'

import React from 'react'

export default function Sidebar() {
  return (
    <div className="card space-y-4">
      <div>
        <h4 className="text-sm font-bold">Filters</h4>
        <p className="text-xs text-muted">(Not implemented) Use backend filters later</p>
      </div>

      <div>
        <label className="block text-xs text-muted">Classification</label>
        <select className="input-field mt-2">
          <option>Any</option>
          <option>Benign</option>
          <option>Suspicious</option>
          <option>Malicious</option>
        </select>
      </div>

      <div>
        <label className="block text-xs text-muted">Category</label>
        <select className="input-field mt-2">
          <option>Any</option>
          <option>Malware</option>
          <option>Phishing</option>
          <option>Spam</option>
        </select>
      </div>

      <div>
        <button className="btn-primary w-full">Apply</button>
      </div>
    </div>
  )
}
