import { HashRouter, Route, Routes, useLocation } from 'react-router-dom'
import { useEffect } from 'react'
import { Shell } from './components/Shell'
import { StoreProvider } from './store/store'
import Landing from './pages/Landing'
import Overview from './pages/Overview'
import Data from './pages/Data'
import Apps from './pages/Apps'
import Rules from './pages/Rules'
import Activity from './pages/Activity'
import Alerts from './pages/Alerts'

function ScrollTop() {
  const { pathname } = useLocation()
  useEffect(() => { window.scrollTo(0, 0) }, [pathname])
  return null
}

export default function App() {
  return (
    <HashRouter>
      <ScrollTop />
      <StoreProvider>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/app" element={<Shell />}>
            <Route index element={<Overview />} />
            <Route path="data" element={<Data />} />
            <Route path="apps" element={<Apps />} />
            <Route path="rules" element={<Rules />} />
            <Route path="activity" element={<Activity />} />
            <Route path="alerts" element={<Alerts />} />
          </Route>
        </Routes>
      </StoreProvider>
    </HashRouter>
  )
}
