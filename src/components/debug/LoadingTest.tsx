'use client'

import React from 'react'

export const LoadingTest: React.FC = () => {
  return (
    <div className="min-h-screen bg-gray-900 text-white flex items-center justify-center">
      <div className="text-center space-y-6">
        {/* Main Heading */}
        <h1 className="text-4xl font-bold">
          <span className="bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 bg-clip-text text-transparent">
            🔥 ADTrapper
          </span>
        </h1>

        {/* Loading Indicator */}
        <div className="flex items-center justify-center space-x-2">
          <div className="w-4 h-4 bg-blue-500 rounded-full animate-bounce"></div>
          <div className="w-4 h-4 bg-blue-500 rounded-full animate-bounce" style={{animationDelay: '0.1s'}}></div>
          <div className="w-4 h-4 bg-blue-500 rounded-full animate-bounce" style={{animationDelay: '0.2s'}}></div>
        </div>

        {/* Status */}
        <p className="text-xl text-gray-300">
          Loading Security Platform...
        </p>

        {/* Simple status */}
        <div className="text-sm text-gray-400">
          ✅ System Ready
        </div>
      </div>
    </div>
  )
}

export default LoadingTest
