import './globals.css'
import React from 'react'

export const metadata = {
  title: 'Threat Intel Dashboard',
  description: 'Search IPs and Domains — quick verdicts and historical data.'
}

export default function RootLayout({ children }: { children: React.ReactNode }){
  return (
    <html lang="en">
      <body>
        <div className="min-h-screen bg-dark text-light">
          <main className="max-w-7xl mx-auto p-6">
            {children}
          </main>
        </div>
      </body>
    </html>
  )
}
