'use client'

import React from 'react'

interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg' | 'xl'
  color?: 'blue' | 'red' | 'green' | 'purple' | 'orange'
  text?: string
}

const sizeClasses = {
  sm: 'w-4 h-4',
  md: 'w-8 h-8',
  lg: 'w-12 h-12',
  xl: 'w-16 h-16'
}

const colorClasses = {
  blue: 'border-blue-500',
  red: 'border-red-500',
  green: 'border-green-500',
  purple: 'border-purple-500',
  orange: 'border-orange-500'
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 'md',
  color = 'blue',
  text
}) => {
  return (
    <div className="flex flex-col items-center justify-center space-y-2">
      <div 
        className={`
          ${sizeClasses[size]} 
          ${colorClasses[color]} 
          border-4 border-t-transparent rounded-full animate-spin
        `}
      />
      {text && (
        <p className="text-sm text-gray-600 dark:text-gray-400 animate-pulse">
          {text}
        </p>
      )}
    </div>
  )
}

export default LoadingSpinner
