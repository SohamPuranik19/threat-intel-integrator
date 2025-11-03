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
      {/* Animated matrix-style background - MORE VISIBLE */}
      <div className="fixed inset-0 opacity-15">
        <div className="absolute inset-0 animate-grid-flow" style={{
          backgroundImage: `
            repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255, 140, 0, 0.08) 2px, rgba(255, 140, 0, 0.08) 4px),
            repeating-linear-gradient(90deg, transparent, transparent 2px, rgba(255, 140, 0, 0.08) 2px, rgba(255, 140, 0, 0.08) 4px)
          `,
          backgroundSize: '50px 50px'
        }}></div>
      </div>

      {/* Animated floating particles - LARGER & BRIGHTER */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="particle particle-1"></div>
        <div className="particle particle-2"></div>
        <div className="particle particle-3"></div>
        <div className="particle particle-4"></div>
        <div className="particle particle-5"></div>
        <div className="particle particle-6"></div>
        <div className="particle particle-7"></div>
        <div className="particle particle-8"></div>
      </div>

      {/* Animated orange glows - BRIGHTER */}
      <div className="fixed top-0 right-0 w-[500px] h-[500px] bg-orange-500/10 rounded-full blur-3xl animate-pulse-slow"></div>
      <div className="fixed bottom-0 left-0 w-[500px] h-[500px] bg-orange-600/10 rounded-full blur-3xl animate-pulse-slower"></div>

      {/* Animated circuit lines - MORE VISIBLE */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        <svg className="w-full h-full">
          <line x1="0" y1="15%" x2="100%" y2="15%" stroke="rgba(255, 140, 0, 0.3)" strokeWidth="2" className="animate-dash" />
          <line x1="0" y1="35%" x2="100%" y2="35%" stroke="rgba(255, 140, 0, 0.25)" strokeWidth="2" className="animate-dash-slow" />
          <line x1="0" y1="55%" x2="100%" y2="55%" stroke="rgba(255, 140, 0, 0.3)" strokeWidth="2" className="animate-dash" />
          <line x1="0" y1="75%" x2="100%" y2="75%" stroke="rgba(255, 140, 0, 0.25)" strokeWidth="2" className="animate-dash-slower" />
          <line x1="0" y1="90%" x2="100%" y2="90%" stroke="rgba(255, 140, 0, 0.3)" strokeWidth="2" className="animate-dash" />
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

        @keyframes float {
          0%, 100% {
            transform: translateY(0) translateX(0);
          }
          25% {
            transform: translateY(-20px) translateX(10px);
          }
          50% {
            transform: translateY(-10px) translateX(-10px);
          }
          75% {
            transform: translateY(-15px) translateX(5px);
          }
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

        .particle {
          position: absolute;
          width: 4px;
          height: 4px;
          background: rgba(255, 140, 0, 0.8);
          border-radius: 50%;
          box-shadow: 0 0 20px rgba(255, 140, 0, 1), 0 0 40px rgba(255, 140, 0, 0.5);
          animation: float 15s ease-in-out infinite;
        }

        .particle-1 {
          top: 10%;
          left: 20%;
          animation-delay: 0s;
          animation-duration: 12s;
        }

        .particle-2 {
          top: 60%;
          left: 80%;
          animation-delay: 2s;
          animation-duration: 15s;
        }

        .particle-3 {
          top: 30%;
          left: 60%;
          animation-delay: 4s;
          animation-duration: 10s;
        }

        .particle-4 {
          top: 80%;
          left: 30%;
          animation-delay: 1s;
          animation-duration: 13s;
        }

        .particle-5 {
          top: 50%;
          left: 10%;
          animation-delay: 3s;
          animation-duration: 14s;
        }

        .particle-6 {
          top: 20%;
          left: 90%;
          animation-delay: 5s;
          animation-duration: 11s;
        }

        .particle-7 {
          top: 70%;
          left: 50%;
          animation-delay: 2.5s;
          animation-duration: 16s;
        }

        .particle-8 {
          top: 40%;
          left: 15%;
          animation-delay: 4.5s;
          animation-duration: 12s;
        }
      `}</style>
    </div>
  )
}
