import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import { BRAND } from './data/mock'
import './styles/global.css'

document.title = `${BRAND} — The OAuth layer for your data and AI agents`

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
