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
      {/* Animated matrix-style grid - MORE VISIBLE */}
      <div className="fixed inset-0 opacity-20">
        <div className="absolute inset-0 animate-grid-flow" style={{
          backgroundImage: `
            repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255, 140, 0, 0.1) 2px, rgba(255, 140, 0, 0.1) 4px),
            repeating-linear-gradient(90deg, transparent, transparent 2px, rgba(255, 140, 0, 0.1) 2px, rgba(255, 140, 0, 0.1) 4px)
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
      </div>

      {/* Animated orange glows - BRIGHTER */}
      <div className="fixed top-0 left-1/2 -translate-x-1/2 w-[600px] h-[600px] bg-orange-500/10 rounded-full blur-3xl animate-pulse-slow"></div>
      <div className="fixed bottom-0 right-0 w-[400px] h-[400px] bg-orange-600/10 rounded-full blur-3xl animate-pulse-slower"></div>

      {/* Animated scan lines - MORE VISIBLE */}
      <div className="fixed inset-0 pointer-events-none opacity-10">
        <div className="h-full w-full animate-scan" style={{
          background: 'linear-gradient(transparent 50%, rgba(255, 140, 0, 0.2) 50%)',
          backgroundSize: '100% 4px'
        }}></div>
      </div>

      {/* Animated circuit lines - MORE VISIBLE */}
      <div className="fixed inset-0 pointer-events-none opacity-20">
        <svg className="w-full h-full">
          <line x1="0" y1="20%" x2="100%" y2="20%" stroke="rgba(255, 140, 0, 0.3)" strokeWidth="2" className="animate-dash" />
          <line x1="0" y1="40%" x2="100%" y2="40%" stroke="rgba(255, 140, 0, 0.25)" strokeWidth="2" className="animate-dash-slow" />
          <line x1="0" y1="60%" x2="100%" y2="60%" stroke="rgba(255, 140, 0, 0.3)" strokeWidth="2" className="animate-dash" />
          <line x1="0" y1="80%" x2="100%" y2="80%" stroke="rgba(255, 140, 0, 0.25)" strokeWidth="2" className="animate-dash-slower" />
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
        @keyframes scan {
          0% {
            transform: translateY(-100%);
          }
          100% {
            transform: translateY(100%);
          }
        }

        .animate-scan {
          animation: scan 8s linear infinite;
        }

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
            transform: translate(-50%, 0) scale(1);
          }
          50% {
            opacity: 0.08;
            transform: translate(-50%, 0) scale(1.1);
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
      `}</style>
    </div>
  )
}
