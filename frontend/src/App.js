import React from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { ToastProvider } from "./components/ui";
import { Layout } from "./components/Layout";
import AppErrorBoundary from "./components/AppErrorBoundary";
import { AuthProvider, useAuth, roleAtLeast } from "./lib/auth";
import Dashboard from "./pages/Dashboard";
import RedScope from "./pages/RedScope";
import EngagementDetail from "./pages/EngagementDetail";
import AgentsPage from "./pages/AgentsPage";
import ModelGatewayPage from "./pages/ModelGatewayPage";
import UsersPage from "./pages/UsersPage";
import NotFound from "./pages/NotFound";
import Login from "./pages/Login";
import { Loading } from "./components/ui";

function ProtectedShell({ children, requires }) {
  const { user } = useAuth();
  const loc = useLocation();
  if (user === null) return <Loading label="Verifying session" />;
  if (user === false) return <Navigate to="/login" replace state={{ from: loc.pathname + loc.search }} />;
  if (requires && !roleAtLeast(user, requires)) {
    return (
      <div className="p-10 text-center">
        <div className="h-font text-2xl uppercase text-kill mb-2">Forbidden</div>
        <div className="text-sm text-muted">This page requires role <b className="text-white">{requires}</b> or higher.</div>
      </div>
    );
  }
  return <Layout>{children}</Layout>;
}

export default function App() {
  return (
    <AppErrorBoundary>
      <ToastProvider>
        <AuthProvider>
          <BrowserRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
            <Routes>
              <Route path="/login" element={<Login />} />
              <Route path="/" element={<ProtectedShell><Dashboard /></ProtectedShell>} />
              <Route path="/red-scope" element={<ProtectedShell><RedScope /></ProtectedShell>} />
              <Route path="/engagements/:id" element={<ProtectedShell><EngagementDetail /></ProtectedShell>} />
              <Route path="/agents" element={<ProtectedShell><AgentsPage /></ProtectedShell>} />
              <Route path="/model-gateway" element={<ProtectedShell><ModelGatewayPage /></ProtectedShell>} />
              <Route path="/users" element={<ProtectedShell requires="admin"><UsersPage /></ProtectedShell>} />
              <Route path="*" element={<ProtectedShell><NotFound /></ProtectedShell>} />
            </Routes>
          </BrowserRouter>
        </AuthProvider>
      </ToastProvider>
    </AppErrorBoundary>
  );
}
