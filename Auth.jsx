import React, { useState } from 'react';
import { 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword, 
  signInWithPopup, 
  GoogleAuthProvider,
  sendPasswordResetEmail // NEW: Import reset function
} from "firebase/auth";
import { auth } from './firebase';

// Initialize the Google Auth Provider
const googleProvider = new GoogleAuthProvider();

const Auth = () => {
  const [isLogin, setIsLogin] = useState(true);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMessage, setSuccessMessage] = useState(null); // NEW: State for success messages

  const switchMode = () => {
    setIsLogin(prev => !prev);
    setError(null);
    setSuccessMessage(null);
  };

  const handleAuth = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setSuccessMessage(null);

    try {
      if (isLogin) {
        // Login functionality
        await signInWithEmailAndPassword(auth, email, password);
      } else {
        // Signup functionality
        await createUserWithEmailAndPassword(auth, email, password);
      }
    } catch (err) {
      console.error(err);
      setError(err.message.replace("Firebase: ", "").replace(/\(auth.*\)/, "").trim());
    } finally {
      setLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setLoading(true);
    setError(null);
    setSuccessMessage(null);

    try {
      await signInWithPopup(auth, googleProvider);
    } catch (err) {
      console.error(err);
      setError(err.message.replace("Firebase: ", "").replace(/\(auth.*\)/, "").trim());
    } finally {
      setLoading(false);
    }
  };
  
  // NEW: Function to handle password reset email
  const handleForgotPassword = async () => {
      // Check if email field is empty before attempting reset
      if (!email) {
          setError("Please enter your email address to receive the password reset link.");
          return;
      }
      
      setLoading(true);
      setError(null);
      setSuccessMessage(null);

      try {
          await sendPasswordResetEmail(auth, email);
          setSuccessMessage(`Password reset link sent to ${email}. Check your inbox!`);
      } catch (err) {
          console.error(err);
          setError(err.message.replace("Firebase: ", "").replace(/\(auth.*\)/, "").trim());
      } finally {
          setLoading(false);
      }
  }

  const title = isLogin ? "Welcome Back to ZipLink" : "Create Your ZipLink Account";
  const buttonText = isLogin ? "Sign In" : "Sign Up";

  return (
    <div className="container auth-container">
      {/* Logo and App Name */}
      <div className="logo-header">
        <img 
          src="/ZipLink_logo.jpg" 
          alt="ZipLink Logo" 
          className="auth-logo" 
        />
        <h2>ZipLink</h2>
      </div>
      
      <h3>{title}</h3>
      
      {/* Main Auth Form */}
      <form onSubmit={handleAuth}>
        <input
          type="email"
          placeholder="Email Address"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        
        {/* Only show password field for sign in/up (hide when sending reset email) */}
        {!successMessage && (
            <input
                type="password"
                placeholder="Password (min 6 characters)"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
            />
        )}
        
        {/* Forgot Password Link - Only visible on Login mode */}
        {isLogin && !successMessage && (
            <a className="forgot-password-link" onClick={handleForgotPassword}>
                Forgot Password?
            </a>
        )}
        
        <button type="submit" disabled={loading}>
          {loading ? (isLogin ? 'Signing In...' : 'Registering...') : buttonText}
        </button>
      </form>

      {/* Google Sign-In Button */}
      {!successMessage && (
        <>
            <div className="social-login-divider">OR</div>
            <button 
                type="button" 
                className="google-sign-in-button" 
                onClick={handleGoogleSignIn} 
                disabled={loading}
            >
                <svg viewBox="0 0 24 24" className="google-icon">
                    <path d="M22.56 12.25c0-.62-.05-1.22-.15-1.8H12v3.42h6.24c-.26 1.34-1.04 2.47-2.31 3.25l-.26.24 2.74 2.13 2.52.18c1.51-1.39 2.39-3.46 2.39-5.92z" fill="#4285F4"></path>
                    <path d="M12 23c3.21 0 5.89-1.09 7.84-2.95l-2.82-2.18c-.77.5-1.74.8-3.02.8-2.34 0-4.32-1.57-5.04-3.67l-.24-.52-2.8 2.17-.6.58C5.2 21.03 8.35 23 12 23z" fill="#34A853"></path>
                    <path d="M6.96 15.6c-.2-.5-.32-1.02-.32-1.58s.12-1.08.32-1.58L6.4 11.23l-2.84-2.22-.5.1C2.5 10.3 2 11.16 2 12s.5 1.7-1.05 2.87l-.5.1 2.84 2.22.56-1.39z" fill="#FBBC05"></path>
                    <path d="M12 6.95c1.47 0 2.68.5 3.65 1.4L18 5.92c-1.94-1.85-4.63-2.92-7.85-2.92C8.35 3 5.2 4.97 3 7.85l3.36 2.62c.72-2.1 2.7-3.67 5.04-3.67z" fill="#EA4335"></path>
                </svg>
                Sign {isLogin ? 'In' : 'Up'} with Google
            </button>
        </>
      )}

      {error && <p className="error">{error}</p>}
      {successMessage && <p className="success-message">{successMessage}</p>}

      <p className="auth-switch-text">
        {isLogin ? "Don't have an account?" : "Already have an account?"}
        <button className="auth-switch-button" onClick={switchMode} disabled={loading}>
          {isLogin ? 'Sign Up' : 'Sign In'}
        </button>
      </p>
    </div>
  );
};

export default Auth;