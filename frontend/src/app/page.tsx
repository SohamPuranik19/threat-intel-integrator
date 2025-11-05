'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { LogOut, User, Shield, Activity, Database, Terminal } from 'lucide-react'
import SearchBar from '../components/SearchBar'
import QuickVerdict from '../components/QuickVerdict'
import DataTable from '../components/DataTable'
import Charts from '../components/Charts'
import Sidebar from '../components/Sidebar'

export default function Page(){
  const [result, setResult] = useState<any>(null)
  const [allData, setAllData] = useState<any[]>([])
  const [currentUser, setCurrentUser] = useState<string | null>(null)
  const router = useRouter()

  useEffect(() => {
    // Check authentication
    const isAuthenticated = localStorage.getItem('isAuthenticated')
    const user = localStorage.getItem('currentUser')
    
    if (isAuthenticated !== 'true') {
      router.push('/login')
    } else {
      setCurrentUser(user)
    }
  }, [router])

  function handleLogout() {
    localStorage.removeItem('isAuthenticated')
    localStorage.removeItem('currentUser')
    router.push('/login')
  }

  // Don't render until we verify authentication
  if (!currentUser) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="flex items-center gap-3 px-6 py-4 bg-gray-900 border border-orange-500/30 rounded-xl">
          <div className="w-6 h-6 border-2 border-orange-500/30 border-t-orange-500 rounded-full animate-spin"></div>
          <div className="text-orange-500 text-lg font-medium">Initializing System...</div>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-black text-white relative overflow-hidden">
      {/* Multi-layer animated background - MUCH BRIGHTER */}
      <div className="fixed inset-0 pointer-events-none -z-10">
        {/* Matrix-style falling code - VERY VISIBLE */}
        <canvas id="matrix-canvas" className="absolute inset-0 w-full h-full opacity-50"></canvas>

        {/* Radar with increased visibility */}
        <div className="radar-wrapper opacity-80">
          <div className="radar">
            <div className="ring ring-1"></div>
            <div className="ring ring-2"></div>
            <div className="ring ring-3"></div>
            <div className="sweep" />
            <div className="blip b1" />
            <div className="blip b2" />
            <div className="blip b3" />
            <div className="blip b4" />
          </div>
        </div>

        {/* MUCH BRIGHTER ambient glows */}
        <div className="fixed top-0 right-0 w-[500px] h-[500px] bg-orange-500/30 rounded-full blur-3xl animate-pulse-slow" />
        <div className="fixed bottom-0 left-0 w-[500px] h-[500px] bg-orange-600/30 rounded-full blur-3xl animate-pulse-slower" />
      </div>

      {/* Animated circuit lines - MORE VISIBLE */}
      <div className="fixed inset-0 pointer-events-none opacity-30">
        <svg className="w-full h-full">
          <line x1="0" y1="15%" x2="100%" y2="15%" stroke="rgba(255, 140, 0, 0.5)" strokeWidth="2" className="animate-dash" />
          <line x1="0" y1="35%" x2="100%" y2="35%" stroke="rgba(255, 140, 0, 0.4)" strokeWidth="2" className="animate-dash-slow" />
          <line x1="0" y1="55%" x2="100%" y2="55%" stroke="rgba(255, 140, 0, 0.5)" strokeWidth="2" className="animate-dash" />
          <line x1="0" y1="75%" x2="100%" y2="75%" stroke="rgba(255, 140, 0, 0.4)" strokeWidth="2" className="animate-dash-slower" />
          <line x1="0" y1="90%" x2="100%" y2="90%" stroke="rgba(255, 140, 0, 0.5)" strokeWidth="2" className="animate-dash" />
        </svg>
      </div>

      <div className="relative z-10 grid grid-cols-1 lg:grid-cols-4 gap-6 p-6">
        <aside className="lg:col-span-1">
          <Sidebar />
        </aside>
        
        <section className="lg:col-span-3 space-y-6">
          {/* Professional Header */}
          <div className="bg-gradient-to-br from-gray-900 to-black border border-orange-500/20 rounded-2xl shadow-2xl shadow-orange-500/10 overflow-hidden">
            {/* Top accent */}
            <div className="h-1 bg-gradient-to-r from-transparent via-orange-500 to-transparent animate-glow"></div>
            
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <div className="flex items-center gap-4">
                  <div className="relative">
                    <div className="absolute inset-0 bg-orange-500 rounded-xl blur-md opacity-50"></div>
                    <div className="relative bg-gradient-to-br from-orange-500 to-orange-600 p-3 rounded-xl shadow-lg">
                      <Shield size={32} className="text-white" />
                    </div>
                  </div>
                  <div>
                    <p className="text-sm text-gray-400 mb-1">
                      Advanced Threat Intelligence
                    </p>
                    <h1 className="text-3xl font-bold bg-gradient-to-r from-orange-400 to-orange-600 bg-clip-text text-transparent">
                      Security Command Center
                    </h1>
                  </div>
                </div>
                
                <div className="flex items-center gap-3">
                  <div className="flex items-center gap-2 px-4 py-2 bg-gray-900 border border-orange-500/30 rounded-lg text-sm">
                    <User size={16} className="text-orange-500" />
                    <span className="text-gray-300 font-medium">{currentUser}</span>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/30 rounded-lg text-red-400 hover:bg-red-500/20 transition-all text-sm font-medium"
                    title="Logout"
                  >
                    <LogOut size={16} />
                    <span>Logout</span>
                  </button>
                </div>
              </div>
              
              {/* System stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="group relative bg-gray-900/50 border border-orange-500/20 rounded-xl p-4 hover:border-orange-500/40 transition-all">
                  <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-transparent rounded-xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative flex items-center gap-3">
                    <div className="p-2 bg-orange-500/10 rounded-lg">
                      <Activity size={24} className="text-orange-500" />
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 font-medium">System Status</div>
                      <div className="text-lg font-bold text-white flex items-center gap-2">
                        <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                        Online
                      </div>
                    </div>
                  </div>
                </div>
                
                <div className="group relative bg-gray-900/50 border border-orange-500/20 rounded-xl p-4 hover:border-orange-500/40 transition-all">
                  <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-transparent rounded-xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative flex items-center gap-3">
                    <div className="p-2 bg-orange-500/10 rounded-lg">
                      <Database size={24} className="text-orange-500" />
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 font-medium">Threat Records</div>
                      <div className="text-lg font-bold text-white">{allData.length}</div>
                    </div>
                  </div>
                </div>
                
                <div className="group relative bg-gray-900/50 border border-orange-500/20 rounded-xl p-4 hover:border-orange-500/40 transition-all">
                  <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-transparent rounded-xl opacity-0 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative flex items-center gap-3">
                    <div className="p-2 bg-orange-500/10 rounded-lg">
                      <Terminal size={24} className="text-orange-500" />
                    </div>
                    <div>
                      <div className="text-xs text-gray-500 font-medium">Active Scans</div>
                      <div className="text-lg font-bold text-orange-500">Running</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <SearchBar onResult={(r:any)=>{ setResult(r); }} onFetchAll={(rows:any[])=>setAllData(rows)} />

          {result && <QuickVerdict data={result} />}

          <Charts data={allData} />

          <DataTable data={allData} />
        </section>
      </div>

      <style jsx>{`
        @keyframes grid-flow {
          0% {
            transform: translateY(0) translateX(0);
          }
          100% {
            transform: translateY(50px) translateX(50px);
          }
        }

        .animate-grid-flow {
          /* kept for backward compatibility, unused when radar is active */
          animation: grid-flow 20s linear infinite;
        }

        @keyframes pulse-slow {
          0%, 100% {
            opacity: 0.05;
            transform: scale(1);
          }
          50% {
            opacity: 0.08;
            transform: scale(1.1);
          }
        }

        .animate-pulse-slow {
          animation: pulse-slow 4s ease-in-out infinite;
        }

        @keyframes pulse-slower {
          0%, 100% {
            opacity: 0.05;
            transform: scale(1);
          }
          50% {
            opacity: 0.08;
            transform: scale(1.15);
          }
        }

        .animate-pulse-slower {
          animation: pulse-slower 6s ease-in-out infinite;
        }

        /* Radar sweep and blips - MUCH MORE VISIBLE */}
        .radar-wrapper { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; }
        .radar { position: absolute; width: 560px; height: 560px; top: 10%; left: 8%; pointer-events: none; }
        .radar .ring { position: absolute; inset: 0; border-radius: 50%; box-shadow: inset 0 0 60px rgba(249,115,22,0.15); border: 2px solid rgba(249,115,22,0.25); }
        .radar .ring.ring-2 { transform: scale(0.66); left: 17%; top: 17%; width: 66%; height: 66%; }
        .radar .ring.ring-3 { transform: scale(0.33); left: 33%; top: 33%; width: 33%; height: 33%; }
        .radar .sweep { position: absolute; inset: 0; border-radius: 50%; background: conic-gradient(rgba(249,115,22,0.4), rgba(249,115,22,0.2) 20%, transparent 40%); filter: blur(15px); transform-origin: 50% 50%; animation: radar-spin 4s linear infinite; }
        .radar .blip { position: absolute; width: 16px; height: 16px; background: #f97316; border-radius: 50%; box-shadow: 0 0 25px rgba(249,115,22,1), 0 0 50px rgba(249,115,22,0.7); }
        .radar .b1 { left: 60%; top: 22%; animation: blip 3s ease-in-out infinite; }
        .radar .b2 { left: 28%; top: 40%; animation: blip 3.5s ease-in-out 0.6s infinite; }
        .radar .b3 { left: 46%; top: 68%; animation: blip 4s ease-in-out 1.2s infinite; }
        .radar .b4 { left: 72%; top: 52%; animation: blip 3.2s ease-in-out 0.9s infinite; }

        @keyframes radar-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        @keyframes blip {
          0%, 100% { transform: scale(0.8); opacity: 0.5; }
          50% { transform: scale(1.5); opacity: 1; }
        }

        @keyframes dash {
          0% {
            stroke-dasharray: 0, 100;
          }
          50% {
            stroke-dasharray: 100, 0;
          }
          100% {
            stroke-dasharray: 0, 100;
          }
        }

        .animate-dash {
          stroke-dasharray: 10, 20;
          animation: dash 3s linear infinite;
        }

        .animate-dash-slow {
          stroke-dasharray: 15, 25;
          animation: dash 5s linear infinite;
        }

        .animate-dash-slower {
          stroke-dasharray: 20, 30;
          animation: dash 7s linear infinite;
        }

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

        /* removed floating particle styles in favor of radar blips */
      `}</style>
    </div>
  )
}
