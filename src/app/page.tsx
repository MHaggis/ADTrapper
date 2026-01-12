'use client'

import ADTrapper from '@/components/ADTrapper'
import ConnectionTest from '@/components/debug/ConnectionTest'

export default function Home() {
  return (
    <main className="min-h-screen bg-gray-900 text-white">
      {/* Connection Test - Always visible for monitoring */}
      <ConnectionTest />

      {/* Main ADTrapper Application */}
      <div className="w-full h-screen">
        <ADTrapper />
      </div>
    </main>
  )
}
