import { Navigate, Route, Routes } from "react-router";

import HomePage from "./pages/HomePage.jsx";
import SignUpPage from "./pages/SignUpPage.jsx";
import LoginPage from "./pages/LoginPage.jsx";
import NotificationsPage from "./pages/NotificationsPage.jsx";
import CallPage from "./pages/CallPage.jsx";
import ChatPage from "./pages/ChatPage.jsx";
import OnboardingPage from "./pages/OnboardingPage.jsx";
import FriendsPage from "./pages/FriendsPage.jsx";
import ProfilePage from "./pages/ProfilePage.jsx";

import { Toaster } from "react-hot-toast";

import PageLoader from "./components/PageLoader.jsx";
import useAuthUser from "./hooks/useAuthUser.js";
import Layout from "./components/Layout.jsx";
import { useThemeStore } from "./store/useThemeStore.js";

import VerifyEmailPage from "./pages/VerifyEmailPage.jsx";

import ForgotPasswordPage from "./pages/ForgotPasswordPage.jsx";
import ResetPasswordPage from "./pages/ResetPasswordPage.jsx";

const App = () => {
  const { isLoading, authUser } = useAuthUser();
  const { theme } = useThemeStore();

  const isAuthenticated = Boolean(authUser);
  const isEmailVerified = authUser?.isEmailVerified;
  const isOnboarded = authUser?.isOnboarded;

  const authRedirect = !isAuthenticated
    ? "/login"
    : !isEmailVerified
      ? "/verify-email"
      : !isOnboarded
        ? "/onboarding"
        : "/";

  if (isLoading) return <PageLoader />;

  return (
    <div className="h-screen" data-theme={theme}>
      <Routes>
        {/* PUBLIC ROUTES */}
        <Route
          path="/signup"
          element={
            !isAuthenticated ? <SignUpPage /> : <Navigate to={authRedirect} />
          }
        />

        <Route path="/verify-email" element={<VerifyEmailPage />} />

        <Route
          path="/login"
          element={
            !isAuthenticated ? <LoginPage /> : <Navigate to={authRedirect} />
          }
        />

        <Route
          path="/forgot-password"
          element={
            !isAuthenticated ? <ForgotPasswordPage /> : <Navigate to="/" />
          }
        />

        <Route
          path="/reset-password"
          element={
            !isAuthenticated ? <ResetPasswordPage /> : <Navigate to="/" />
          }
        />

        <Route
          path="/onboarding"
          element={
            isAuthenticated ? (
              !isEmailVerified ? (
                <Navigate to="/verify-email" />
              ) : !isOnboarded ? (
                <OnboardingPage />
              ) : (
                <Navigate to="/" />
              )
            ) : (
              <Navigate to="/login" />
            )
          }
        />

        {/* 🔐 PROTECTED ROUTES (WITH LAYOUT) */}
        <Route
          element={
            isAuthenticated && isEmailVerified && isOnboarded ? (
              <Layout />
            ) : (
              <Navigate to={authRedirect} />
            )
          }
        >
          <Route path="/" element={<HomePage />} />
          <Route path="/friends" element={<FriendsPage />} />
          <Route path="/notifications" element={<NotificationsPage />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Route>

        {/* CALL & CHAT (NO SIDEBAR) */}
        <Route
          element={
            isAuthenticated && isEmailVerified && isOnboarded ? (
              <Layout showSidebar={false} />
            ) : (
              <Navigate to={authRedirect} />
            )
          }
        >
          <Route path="/chat/:id" element={<ChatPage />} />
        </Route>

        <Route
          path="/call/:id"
          element={
            isAuthenticated && isEmailVerified && isOnboarded ? (
              <CallPage />
            ) : (
              <Navigate to={authRedirect} />
            )
          }
        />
      </Routes>

      <Toaster />
    </div>
  );
};
export default App;
