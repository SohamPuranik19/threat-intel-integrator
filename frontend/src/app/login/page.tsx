'use client'

import React, { useState, useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { Shield, Eye, EyeOff, Lock, Mail } from 'lucide-react'

export default function LoginPage() {
  const router = useRouter()
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [isLogin, setIsLogin] = useState(true)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [showPassword, setShowPassword] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setLoading(true)
    setError(null)
    setSuccess(null)

    try {
      if (isLogin) {
        const storedUser = localStorage.getItem('user_' + email)
        
        if (!storedUser) {
          throw new Error('User not found. Please register first.')
        }

        const userData = JSON.parse(storedUser)
        
        if (userData.password !== password) {
          throw new Error('Invalid password. Please try again.')
        }

        localStorage.setItem('currentUser', email)
        localStorage.setItem('isAuthenticated', 'true')
        
        setSuccess('Authentication successful. Redirecting...')
        setTimeout(() => {
          router.push('/')
        }, 1000)
      } else {
        const existingUser = localStorage.getItem('user_' + email)
        
        if (existingUser) {
          throw new Error('User already exists. Please login.')
        }

        const userData = {
          email,
          password,
          createdAt: new Date().toISOString()
        }
        
        localStorage.setItem('user_' + email, JSON.stringify(userData))
        
        setSuccess('Account created successfully. You can now login.')
        setIsLogin(true)
        setPassword('')
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-6 relative overflow-hidden">
      {/* Multi-layer animated background - MAXIMUM VISIBILITY */}
      <div className="fixed inset-0 pointer-events-none -z-10">
        {/* Matrix-style falling code - VERY VISIBLE */}
        <canvas id="matrix-canvas" className="absolute inset-0 w-full h-full opacity-50"></canvas>

        {/* Hexagonal grid overlay - BRIGHTER */}
        <div className="hex-grid opacity-60"></div>

        {/* Enhanced radar with MORE visibility */}
        <div className="radar-wrapper opacity-80">
          <div className="radar">
            <div className="ring ring-1"></div>
            <div className="ring ring-2"></div>
            <div className="ring ring-3"></div>
            <div className="ring ring-4"></div>
            <div className="sweep" />
            <div className="blip b1" />
            <div className="blip b2" />
            <div className="blip b3" />
            <div className="blip b4" />
            <div className="blip b5" />
            <div className="blip b6" />
            <div className="blip b7" />
            <div className="blip b8" />
          </div>
        </div>

        {/* Animated data streams - BRIGHTER */}
        <div className="data-streams opacity-80">
          <div className="stream s1"></div>
          <div className="stream s2"></div>
          <div className="stream s3"></div>
          <div className="stream s4"></div>
          <div className="stream s5"></div>
        </div>

        {/* Network nodes with connecting lines - BRIGHTER */}
        <svg className="network-nodes opacity-60" width="100%" height="100%">
          <line className="node-line nl1" x1="15%" y1="20%" x2="35%" y2="40%" />
          <line className="node-line nl2" x1="65%" y1="30%" x2="80%" y2="60%" />
          <line className="node-line nl3" x1="20%" y1="70%" x2="50%" y2="80%" />
          <line className="node-line nl4" x1="70%" y1="20%" x2="85%" y2="45%" />
          <circle className="node n1" cx="15%" cy="20%" r="4" />
          <circle className="node n2" cx="35%" cy="40%" r="5" />
          <circle className="node n3" cx="65%" cy="30%" r="4" />
          <circle className="node n4" cx="80%" cy="60%" r="5" />
          <circle className="node n5" cx="20%" cy="70%" r="4" />
          <circle className="node n6" cx="50%" cy="80%" r="5" />
          <circle className="node n7" cx="70%" cy="20%" r="4" />
          <circle className="node n8" cx="85%" cy="45%" r="5" />
        </svg>

        {/* Enhanced ambient glows - MUCH BRIGHTER */}
        <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-orange-500/30 rounded-full blur-3xl animate-pulse-slow" />
        <div className="fixed bottom-0 right-0 w-[400px] h-[400px] bg-orange-600/30 rounded-full blur-3xl animate-pulse-slower" />
      </div>

      {/* Animated circuit lines - BRIGHTER */}
      <div className="fixed inset-0 pointer-events-none opacity-30">
        <svg className="w-full h-full">
          <line x1="0" y1="20%" x2="100%" y2="20%" stroke="rgba(249, 115, 22, 0.5)" strokeWidth="1.5" className="animate-dash" />
          <line x1="0" y1="60%" x2="100%" y2="60%" stroke="rgba(234, 88, 12, 0.5)" strokeWidth="1.5" className="animate-dash-slow" />
        </svg>
      </div>

      <div className="w-full max-w-md relative z-10">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-orange-500 to-orange-600 rounded-2xl mb-6 shadow-lg shadow-orange-500/50 relative">
            <div className="absolute inset-0 bg-orange-500 rounded-2xl blur-md opacity-50 animate-pulse"></div>
            <Shield size={40} className="text-white relative z-10" />
          </div>
          
          <h1 className="text-4xl font-bold mb-3 bg-gradient-to-r from-orange-400 via-orange-500 to-orange-600 bg-clip-text text-transparent">
            Threat Intelligence
          </h1>
          <p className="text-gray-400 text-lg">
            Advanced Security Platform
          </p>
          <div className="mt-4 flex items-center justify-center gap-2 text-sm text-orange-500/70">
            <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse"></div>
            <span>Secure Connection</span>
            <div className="w-2 h-2 bg-orange-500 rounded-full animate-pulse"></div>
          </div>
        </div>

        {/* Login Card */}
        <div className="bg-gradient-to-br from-gray-900 to-black border border-orange-500/20 rounded-2xl shadow-2xl shadow-orange-500/10 overflow-hidden backdrop-blur-sm">
          {/* Top border accent */}
          <div className="h-1 bg-gradient-to-r from-transparent via-orange-500 to-transparent"></div>
          
          <div className="p-8">
            {/* Mode Toggle */}
            <div className="flex gap-3 mb-8">
              <button
                type="button"
                onClick={() => {
                  setIsLogin(true)
                  setError(null)
                  setSuccess(null)
                }}
                className={`flex-1 py-3 px-6 rounded-xl font-semibold transition-all ${
                  isLogin
                    ? 'bg-gradient-to-r from-orange-500 to-orange-600 text-white shadow-lg shadow-orange-500/30'
                    : 'bg-gray-800/50 text-gray-400 hover:bg-gray-800 border border-gray-700'
                }`}
              >
                <Lock size={18} className="inline mr-2" />
                Sign In
              </button>
              <button
                type="button"
                onClick={() => {
                  setIsLogin(false)
                  setError(null)
                  setSuccess(null)
                }}
                className={`flex-1 py-3 px-6 rounded-xl font-semibold transition-all ${
                  !isLogin
                    ? 'bg-gradient-to-r from-orange-500 to-orange-600 text-white shadow-lg shadow-orange-500/30'
                    : 'bg-gray-800/50 text-gray-400 hover:bg-gray-800 border border-gray-700'
                }`}
              >
                <Mail size={18} className="inline mr-2" />
                Register
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Email Field */}
              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-300">
                  Email Address
                </label>
                <div className="relative">
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="your.email@company.com"
                    required
                    className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 pl-11 text-white placeholder-gray-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all"
                  />
                  <Mail size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                </div>
              </div>

              {/* Password Field */}
              <div className="space-y-2">
                <label className="block text-sm font-medium text-gray-300">
                  Password
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter your password"
                    required
                    minLength={6}
                    className="w-full bg-gray-900/50 border border-gray-700 rounded-lg px-4 py-3 pl-11 pr-11 text-white placeholder-gray-500 focus:border-orange-500 focus:ring-2 focus:ring-orange-500/20 focus:outline-none transition-all"
                  />
                  <Lock size={18} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-orange-500 transition-colors"
                  >
                    {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                  </button>
                </div>
                {!isLogin && (
                  <p className="text-xs text-gray-500">
                    Minimum 6 characters required
                  </p>
                )}
              </div>

              {/* Error Message */}
              {error && (
                <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/30 backdrop-blur-sm">
                  <p className="text-sm text-red-400">{error}</p>
                </div>
              )}

              {/* Success Message */}
              {success && (
                <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/30 backdrop-blur-sm">
                  <p className="text-sm text-orange-400">{success}</p>
                </div>
              )}

              {/* Submit Button */}
              <button
                type="submit"
                disabled={loading}
                className="w-full bg-gradient-to-r from-orange-500 to-orange-600 hover:from-orange-600 hover:to-orange-700 text-white py-4 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed transition-all shadow-lg shadow-orange-500/30 hover:shadow-orange-500/50 relative overflow-hidden group"
              >
                <div className="absolute inset-0 bg-gradient-to-r from-orange-400 to-orange-500 opacity-0 group-hover:opacity-20 transition-opacity"></div>
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    Processing...
                  </span>
                ) : (
                  isLogin ? 'Access System' : 'Create Account'
                )}
              </button>
            </form>

            {/* Footer */}
            <div className="mt-8 pt-6 border-t border-gray-800">
              <p className="text-center text-xs text-gray-600">
                Enterprise-Grade Security • Encrypted Authentication
              </p>
            </div>
          </div>
        </div>

        {/* Bottom info */}
        <div className="mt-6 text-center">
          <p className="text-sm text-gray-600">Threat Intelligence Platform v2.0</p>
          <p className="text-xs text-gray-700 mt-2">© 2025 Advanced Cyber Security Solutions</p>
        </div>
      </div>

      <style jsx>{`
        /* ENHANCED ANIMATIONS - MAXIMUM VISIBILITY */

        /* Hexagonal grid pattern */
        .hex-grid {
          position: absolute;
          inset: 0;
          background-image: 
            linear-gradient(30deg, transparent 24%, rgba(249,115,22,0.12) 25%, rgba(249,115,22,0.12) 26%, transparent 27%, transparent 74%, rgba(249,115,22,0.12) 75%, rgba(249,115,22,0.12) 76%, transparent 77%, transparent),
            linear-gradient(150deg, transparent 24%, rgba(249,115,22,0.12) 25%, rgba(249,115,22,0.12) 26%, transparent 27%, transparent 74%, rgba(249,115,22,0.12) 75%, rgba(249,115,22,0.12) 76%, transparent 77%, transparent),
            linear-gradient(270deg, transparent 24%, rgba(249,115,22,0.12) 25%, rgba(249,115,22,0.12) 26%, transparent 27%, transparent 74%, rgba(249,115,22,0.12) 75%, rgba(249,115,22,0.12) 76%, transparent 77%, transparent);
          background-size: 100px 173px;
          animation: hex-drift 25s linear infinite;
        }

        @keyframes hex-drift {
          0% { transform: translate(0, 0); }
          100% { transform: translate(50px, 87px); }
        }

        /* Enhanced radar */
        .radar-wrapper { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; }
        .radar { position: absolute; width: 650px; height: 650px; pointer-events: none; }
        .radar .ring { position: absolute; inset: 0; border-radius: 50%; box-shadow: inset 0 0 60px rgba(249,115,22,0.15); border: 2px solid rgba(249,115,22,0.25); }
        .radar .ring.ring-2 { transform: scale(0.75); left: 12.5%; top: 12.5%; width: 75%; height: 75%; }
        .radar .ring.ring-3 { transform: scale(0.5); left: 25%; top: 25%; width: 50%; height: 50%; }
        .radar .ring.ring-4 { transform: scale(0.25); left: 37.5%; top: 37.5%; width: 25%; height: 25%; }
        .radar .sweep { position: absolute; inset: 0; border-radius: 50%; background: conic-gradient(rgba(249,115,22,0.4), rgba(249,115,22,0.2) 20%, transparent 40%); filter: blur(20px); transform-origin: 50% 50%; animation: radar-spin 4s linear infinite; }
        .radar .blip { position: absolute; width: 16px; height: 16px; background: #f97316; border-radius: 50%; box-shadow: 0 0 25px rgba(249,115,22,1), 0 0 50px rgba(249,115,22,0.7); }
        .radar .b1 { left: 60%; top: 22%; animation: blip 3s ease-in-out infinite; }
        .radar .b2 { left: 28%; top: 40%; animation: blip 3.2s ease-in-out 0.3s infinite; }
        .radar .b3 { left: 46%; top: 68%; animation: blip 3.5s ease-in-out 0.6s infinite; }
        .radar .b4 { left: 72%; top: 52%; animation: blip 3.8s ease-in-out 0.9s infinite; }
        .radar .b5 { left: 38%; top: 25%; animation: blip 4s ease-in-out 1.2s infinite; }
        .radar .b6 { left: 68%; top: 75%; animation: blip 3.3s ease-in-out 1.5s infinite; }
        .radar .b7 { left: 15%; top: 60%; animation: blip 3.7s ease-in-out 1.8s infinite; }
        .radar .b8 { left: 80%; top: 35%; animation: blip 3.4s ease-in-out 2.1s infinite; }

        /* Data streams */
        .data-streams { position: absolute; inset: 0; overflow: hidden; }
        .stream { position: absolute; width: 2px; height: 100px; background: linear-gradient(to bottom, transparent, #f97316, transparent); }
        .s1 { left: 10%; animation: stream-fall 4s linear infinite; }
        .s2 { left: 30%; animation: stream-fall 5s linear 0.8s infinite; }
        .s3 { left: 50%; animation: stream-fall 4.5s linear 1.6s infinite; }
        .s4 { left: 70%; animation: stream-fall 5.2s linear 2.4s infinite; }
        .s5 { left: 90%; animation: stream-fall 4.8s linear 3.2s infinite; }

        @keyframes stream-fall {
          0% { transform: translateY(-100%); opacity: 0; }
          10% { opacity: 0.6; }
          90% { opacity: 0.6; }
          100% { transform: translateY(100vh); opacity: 0; }
        }

        /* Network nodes */
        .network-nodes { position: absolute; inset: 0; pointer-events: none; }
        .node { fill: #f97316; opacity: 0.5; animation: node-pulse 4s ease-in-out infinite; }
        .node-line { stroke: #f97316; stroke-width: 1.5; opacity: 0.25; stroke-dasharray: 5, 5; animation: node-pulse 3s ease-in-out infinite; }
        .nl1 { animation-delay: 0s; }
        .nl2 { animation-delay: 0.5s; }
        .nl3 { animation-delay: 1s; }
        .nl4 { animation-delay: 1.5s; }

        @keyframes node-pulse {
          0%, 100% { opacity: 0.25; }
          50% { opacity: 0.6; }
        }

        @keyframes radar-spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }

        @keyframes blip {
          0% { transform: scale(0.8); opacity: 0.5; }
          50% { transform: scale(1.3); opacity: 1; }
          100% { transform: scale(0.8); opacity: 0.5; }
        }

        @keyframes pulse-slow {
          0%, 100% {
            opacity: 0.25;
            transform: translate(-50%, 0) scale(1);
          }
          50% {
            opacity: 0.35;
            transform: translate(-50%, 0) scale(1.1);
          }
        }

        .animate-pulse-slow {
          animation: pulse-slow 4s ease-in-out infinite;
        }

        @keyframes pulse-slower {
          0%, 100% {
            opacity: 0.25;
            transform: scale(1);
          }
          50% {
            opacity: 0.35;
            transform: scale(1.15);
          }
        }

        .animate-pulse-slower {
          animation: pulse-slower 6s ease-in-out infinite;
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
      `}</style>
    </div>
  )
}
