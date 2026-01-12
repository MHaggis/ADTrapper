'use client'

import React, { createContext, useContext, useState, useEffect } from 'react'

interface ThemeContextType {
  darkMode: boolean
  toggleDarkMode: () => void
  setDarkMode: (darkMode: boolean) => void
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

export const useTheme = () => {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within a ThemeProvider')
  }
  return context
}

interface ThemeProviderProps {
  children: React.ReactNode
  defaultDarkMode?: boolean
}

export const ThemeProvider: React.FC<ThemeProviderProps> = ({ 
  children, 
  defaultDarkMode = true 
}) => {
  const [darkMode, setDarkModeState] = useState(defaultDarkMode)

  // Load theme from localStorage on mount
  useEffect(() => {
    const savedTheme = localStorage.getItem('adtrapper-theme')
    if (savedTheme) {
      setDarkModeState(savedTheme === 'dark')
    }
  }, [])

  // Update document class and localStorage when theme changes
  useEffect(() => {
    const root = document.documentElement
    if (darkMode) {
      root.classList.add('dark')
      localStorage.setItem('adtrapper-theme', 'dark')
    } else {
      root.classList.remove('dark')
      localStorage.setItem('adtrapper-theme', 'light')
    }
  }, [darkMode])

  const toggleDarkMode = () => {
    setDarkModeState(prev => !prev)
  }

  const setDarkMode = (isDark: boolean) => {
    setDarkModeState(isDark)
  }

  return (
    <ThemeContext.Provider value={{ darkMode, toggleDarkMode, setDarkMode }}>
      {children}
    </ThemeContext.Provider>
  )
}
