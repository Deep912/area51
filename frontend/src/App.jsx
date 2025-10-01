// frontend/src/App.jsx - With Auto Logout
import { useState, useEffect, useRef } from 'react'
import axios from 'axios'
import Dashboard from './Dashboard'

const API_URL = 'http://192.168.0.131:8000'
const INACTIVITY_TIMEOUT = 5 * 60 * 1000 // 5 minutes in milliseconds

function App() {
  const [isLogin, setIsLogin] = useState(true)
  const [formData, setFormData] = useState({
    email: '', username: '', full_name: '', password: ''
  })
  const [message, setMessage] = useState('')
  const [user, setUser] = useState(null)
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  
  // Auto-logout functionality
  const timeoutRef = useRef(null)
  const lastActivityRef = useRef(Date.now())

  // Reset inactivity timer
  const resetTimeout = () => {
    lastActivityRef.current = Date.now()
    
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
    }
    
    if (token && user) {
      timeoutRef.current = setTimeout(() => {
        console.log('Auto-logout: 5 minutes of inactivity')
        handleAutoLogout()
      }, INACTIVITY_TIMEOUT)
    }
  }

  // Handle auto logout
  const handleAutoLogout = () => {
    setUser(null)
    setToken(null)
    localStorage.removeItem('token')
    localStorage.removeItem('lastActivity')
    setMessage('⏰ Session expired due to inactivity. Please login again.')
    
    // Clear timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }
  }

  // Activity event listeners
  useEffect(() => {
    const events = ['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click']
    
    const handleActivity = () => {
      if (token && user) {
        resetTimeout()
        localStorage.setItem('lastActivity', Date.now().toString())
      }
    }

    // Add event listeners
    events.forEach(event => {
      document.addEventListener(event, handleActivity, true)
    })

    // Initial timeout setup
    if (token && user) {
      resetTimeout()
    }

    // Cleanup
    return () => {
      events.forEach(event => {
        document.removeEventListener(event, handleActivity, true)
      })
      if (timeoutRef.current) {
        clearTimeout(timeoutRef.current)
      }
    }
  }, [token, user])

  // Check for existing session on page load
  useEffect(() => {
    if (token) {
      // Check if session is still valid
      const lastActivity = localStorage.getItem('lastActivity')
      const now = Date.now()
      
      if (lastActivity) {
        const timeSinceActivity = now - parseInt(lastActivity)
        
        if (timeSinceActivity > INACTIVITY_TIMEOUT) {
          // Session expired
          console.log('Session expired on page load')
          handleAutoLogout()
          return
        }
      }

      // Verify token with backend
      axios.get(`${API_URL}/api/dashboard?token=${token}`)
        .then(response => {
          setUser({ full_name: response.data.user })
          resetTimeout()
        })
        .catch(error => {
          console.log('Token verification failed:', error)
          handleAutoLogout()
        })
    }
  }, [])

  // Check session periodically (every minute)
  useEffect(() => {
    const sessionCheck = setInterval(() => {
      if (token && user) {
        const lastActivity = localStorage.getItem('lastActivity')
        const now = Date.now()
        
        if (lastActivity) {
          const timeSinceActivity = now - parseInt(lastActivity)
          
          if (timeSinceActivity > INACTIVITY_TIMEOUT) {
            console.log('Session expired during periodic check')
            handleAutoLogout()
          }
        }
      }
    }, 60000) // Check every minute

    return () => clearInterval(sessionCheck)
  }, [token, user])

  // Handle authentication
  const handleAuth = async (e) => {
    e.preventDefault()
    setLoading(true)
    setMessage('')

    try {
      if (isLogin) {
        const response = await axios.post(`${API_URL}/auth/login`, {
          username: formData.username, password: formData.password
        })
        
        setToken(response.data.access_token)
        localStorage.setItem('token', response.data.access_token)
        localStorage.setItem('lastActivity', Date.now().toString())
        setUser(response.data.user)
        
      } else {
        await axios.post(`${API_URL}/auth/signup`, formData)
        setMessage('Account created successfully! Please login.')
        setIsLogin(true)
        setFormData({ email: '', username: '', full_name: '', password: '' })
      }
    } catch (error) {
      setMessage(error.response?.data?.detail || 'Something went wrong')
    }
    setLoading(false)
  }

  // Manual logout
  const logout = () => {
    setUser(null)
    setToken(null)
    localStorage.removeItem('token')
    localStorage.removeItem('lastActivity')
    setMessage('Logged out successfully')
    setFormData({ email: '', username: '', full_name: '', password: '' })
    
    // Clear timeout
    if (timeoutRef.current) {
      clearTimeout(timeoutRef.current)
      timeoutRef.current = null
    }
  }

  // If user is logged in, show dashboard
  if (user && token) {
    return <Dashboard token={token} onLogout={logout} />
  }

  // Login/Signup Form
  return (
    <div style={{
      minHeight: '100vh',
      background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      padding: '20px'
    }}>
      <div style={{
        background: 'rgba(255, 255, 255, 0.95)',
        backdropFilter: 'blur(10px)',
        borderRadius: '20px',
        padding: '40px',
        width: '100%',
        maxWidth: '450px',
        boxShadow: '0 25px 50px rgba(0, 0, 0, 0.2)',
        border: '1px solid rgba(255, 255, 255, 0.2)'
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '40px' }}>
          <div style={{
            width: '70px', height: '70px',
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            borderRadius: '50%', display: 'flex', alignItems: 'center',
            justifyContent: 'center', margin: '0 auto 20px', fontSize: '1.8rem'
          }}>🛡️</div>
          
          <h1 style={{ 
            fontSize: '2.2rem', margin: '0 0 10px 0',
            background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
            WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
            fontWeight: 'bold'
          }}>
            Area51 Security
          </h1>
          <p style={{ color: '#666', margin: 0, fontSize: '1.1rem' }}>
            Enterprise Security Platform
          </p>
        </div>

        {/* Toggle Login/Signup */}
        <div style={{
          display: 'flex', marginBottom: '30px', borderRadius: '15px',
          overflow: 'hidden', background: '#f1f3f4', padding: '4px'
        }}>
          <button
            onClick={() => {
              setIsLogin(true)
              setMessage('')
            }}
            style={{
              flex: 1, padding: '12px', border: 'none',
              background: isLogin ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : 'transparent',
              color: isLogin ? 'white' : '#666', cursor: 'pointer',
              borderRadius: '12px', fontWeight: 'bold', transition: 'all 0.3s ease'
            }}
          >
            Login
          </button>
          <button
            onClick={() => {
              setIsLogin(false)
              setMessage('')
            }}
            style={{
              flex: 1, padding: '12px', border: 'none',
              background: !isLogin ? 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)' : 'transparent',
              color: !isLogin ? 'white' : '#666', cursor: 'pointer',
              borderRadius: '12px', fontWeight: 'bold', transition: 'all 0.3s ease'
            }}
          >
            Sign Up
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleAuth} style={{
          display: 'flex', flexDirection: 'column', gap: '20px'
        }}>
          {!isLogin && (
            <>
              <div style={{ position: 'relative' }}>
                <input
                  type="email"
                  placeholder="Email Address"
                  value={formData.email}
                  onChange={(e) => setFormData({...formData, email: e.target.value})}
                  style={{
                    width: '100%', padding: '18px 20px 18px 50px',
                    border: '2px solid #e1e5e9', borderRadius: '15px', fontSize: '16px',
                    boxSizing: 'border-box', transition: 'all 0.3s ease', background: '#fafbfc'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#667eea'
                    e.target.style.background = 'white'
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = '#e1e5e9'
                    e.target.style.background = '#fafbfc'
                  }}
                  required
                />
                <span style={{
                  position: 'absolute', left: '18px', top: '50%',
                  transform: 'translateY(-50%)', fontSize: '18px'
                }}>📧</span>
              </div>

              <div style={{ position: 'relative' }}>
                <input
                  type="text"
                  placeholder="Full Name"
                  value={formData.full_name}
                  onChange={(e) => setFormData({...formData, full_name: e.target.value})}
                  style={{
                    width: '100%', padding: '18px 20px 18px 50px',
                    border: '2px solid #e1e5e9', borderRadius: '15px', fontSize: '16px',
                    boxSizing: 'border-box', transition: 'all 0.3s ease', background: '#fafbfc'
                  }}
                  onFocus={(e) => {
                    e.target.style.borderColor = '#667eea'
                    e.target.style.background = 'white'
                  }}
                  onBlur={(e) => {
                    e.target.style.borderColor = '#e1e5e9'
                    e.target.style.background = '#fafbfc'
                  }}
                  required
                />
                <span style={{
                  position: 'absolute', left: '18px', top: '50%',
                  transform: 'translateY(-50%)', fontSize: '18px'
                }}>👤</span>
              </div>
            </>
          )}
          
          <div style={{ position: 'relative' }}>
            <input
              type="text"
              placeholder="Username"
              value={formData.username}
              onChange={(e) => setFormData({...formData, username: e.target.value})}
              style={{
                width: '100%', padding: '18px 20px 18px 50px',
                border: '2px solid #e1e5e9', borderRadius: '15px', fontSize: '16px',
                boxSizing: 'border-box', transition: 'all 0.3s ease', background: '#fafbfc'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#667eea'
                e.target.style.background = 'white'
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#e1e5e9'
                e.target.style.background = '#fafbfc'
              }}
              required
            />
            <span style={{
              position: 'absolute', left: '18px', top: '50%',
              transform: 'translateY(-50%)', fontSize: '18px'
            }}>🔤</span>
          </div>
          
          <div style={{ position: 'relative' }}>
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Password"
              value={formData.password}
              onChange={(e) => setFormData({...formData, password: e.target.value})}
              style={{
                width: '100%', padding: '18px 20px 18px 50px',
                border: '2px solid #e1e5e9', borderRadius: '15px', fontSize: '16px',
                boxSizing: 'border-box', transition: 'all 0.3s ease', background: '#fafbfc',
                paddingRight: '60px'
              }}
              onFocus={(e) => {
                e.target.style.borderColor = '#667eea'
                e.target.style.background = 'white'
              }}
              onBlur={(e) => {
                e.target.style.borderColor = '#e1e5e9'
                e.target.style.background = '#fafbfc'
              }}
              required
            />
            <span style={{
              position: 'absolute', left: '18px', top: '50%',
              transform: 'translateY(-50%)', fontSize: '18px'
            }}>🔒</span>
            
            <button
              type="button"
              onClick={() => setShowPassword(!showPassword)}
              style={{
                position: 'absolute', right: '15px', top: '50%',
                transform: 'translateY(-50%)', background: 'none',
                border: 'none', cursor: 'pointer', fontSize: '18px'
              }}
            >
              {showPassword ? '🙈' : '👁️'}
            </button>
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              padding: '18px',
              background: loading 
                ? '#ccc' 
                : 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
              border: 'none', borderRadius: '15px', color: 'white',
              fontSize: '18px', fontWeight: 'bold',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.3s ease',
              boxShadow: loading ? 'none' : '0 10px 20px rgba(102, 126, 234, 0.3)'
            }}
            onMouseOver={(e) => {
              if (!loading) {
                e.target.style.transform = 'translateY(-2px)'
                e.target.style.boxShadow = '0 15px 30px rgba(102, 126, 234, 0.4)'
              }
            }}
            onMouseOut={(e) => {
              if (!loading) {
                e.target.style.transform = 'translateY(0)'
                e.target.style.boxShadow = '0 10px 20px rgba(102, 126, 234, 0.3)'
              }
            }}
          >
            {loading ? (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px' }}>
                <div style={{
                  width: '20px', height: '20px',
                  border: '2px solid #ffffff30',
                  borderTop: '2px solid white',
                  borderRadius: '50%',
                  animation: 'spin 1s linear infinite'
                }}></div>
                Please wait...
              </div>
            ) : (
              `${isLogin ? '🚀 Login' : '✨ Create Account'}`
            )}
          </button>
        </form>

        {/* Auto Logout Warning */}
        {user && token && (
          <div style={{
            marginTop: '20px', padding: '12px 16px', background: '#fff3cd',
            border: '1px solid #ffeaa7', borderRadius: '12px', textAlign: 'center'
          }}>
            <span style={{ fontSize: '14px', color: '#856404' }}>
              ⏰ Session will expire after 5 minutes of inactivity
            </span>
          </div>
        )}

        {/* Message */}
        {message && (
          <div style={{
            marginTop: '25px', padding: '15px 20px', borderRadius: '15px',
            background: message.includes('Welcome') || message.includes('successfully') ? 
              'linear-gradient(135deg, #51cf66 0%, #40c057 100%)' :
              message.includes('expired') || message.includes('inactivity') ?
                'linear-gradient(135deg, #ffa502 0%, #ff6348 100%)' :
                'linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%)',
            color: 'white', textAlign: 'center', fontWeight: 'bold',
            boxShadow: '0 5px 15px rgba(0, 0, 0, 0.1)'
          }}>
            {message}
          </div>
        )}
      </div>
      
      {/* CSS Animation */}
      <style>
        {`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}
      </style>
    </div>
  )
}

export default App
