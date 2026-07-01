import { useState, useEffect } from 'react';
import { onAuthStateChanged, signOut } from "firebase/auth";
import './App.css';
import Auth from './Auth.jsx';
import Dashboard from './Dashboard.jsx';
import { auth } from './firebase.js';

// Key for saving view preference
const VIEW_STORAGE_KEY = 'ziplink_current_view';

function App() {
  const [longUrl, setLongUrl] = useState('');
  const [customAlias, setCustomAlias] = useState('');
  const [linkPassword, setLinkPassword] = useState('');
  const [expirationDate, setExpirationDate] = useState('');
  const [shortUrl, setShortUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [currentUser, setCurrentUser] = useState(null);
  const [authLoading, setAuthLoading] = useState(true);
  const [showAdvancedOptions, setShowAdvancedOptions] = useState(false); // NEW: State for advanced options toggle

  const initialView = localStorage.getItem(VIEW_STORAGE_KEY) || 'shortener';
  const [currentView, setCurrentView] = useState(initialView);

  const updateCurrentView = (view) => {
    setCurrentView(view);
    localStorage.setItem(VIEW_STORAGE_KEY, view);
  };

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setAuthLoading(false);
      if (!user) {
        updateCurrentView('shortener');
      }
    });
    return () => unsubscribe();
  }, []);

  const handleLogout = async () => {
    try {
      await signOut(auth);
    } catch (e) {
      console.error("Error signing out:", e);
    }
  };

  const handleCustomAliasChange = (e) => {
    const cleanedValue = e.target.value.replace(/[^a-zA-Z0-9_-]/g, '');
    setCustomAlias(cleanedValue);
  };


  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setShortUrl('');

    const userId = currentUser?.uid;
    if (!userId) {
        setError("You must be logged in to shorten a URL.");
        setLoading(false);
        return;
    }

    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/shorten`,  {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            longUrl,
            customAlias: customAlias,
            linkPassword: linkPassword,
            expirationDate: expirationDate,
            userId: userId
        }),
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Something went wrong');
      }

      const data = await response.json();
      setShortUrl(data.shortUrl);
      // Clear fields and hide advanced options on success
      setCustomAlias('');
      setLongUrl('');
      setLinkPassword('');
      setExpirationDate('');
      setShowAdvancedOptions(false);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  if (authLoading) {
    return (
      <div className="loading-screen">
        Authenticating...
      </div>
    );
  }

  if (!currentUser) {
    return (
      <div className="container">
        <Auth />
      </div>
    );
  }

  if (currentView === 'dashboard') {
    return (
      <Dashboard
        currentUser={currentUser}
        handleLogout={handleLogout}
        setCurrentView={updateCurrentView}
      />
    );
  }

  return (
    <div className="container main-app">
      <div className="app-header">
        <img src="/ZipLink_logo.jpg" alt="ZipLink Logo" className="main-app-logo" />

        <div className="user-info">
          <button className="view-switch-button" onClick={() => updateCurrentView('dashboard')}>
            View Dashboard
          </button>
          <button className="logout-button" onClick={handleLogout}>Log Out</button>
        </div>
      </div>

      <div className="shortener-area">
        <h3 className="app-tagline">Long links, zipped in a blink</h3>
        <h2 className="shortener-title">Shorten Your URL</h2>

        <form onSubmit={handleSubmit}>
          {/* Main URL input is always visible */}
          <div className="input-group">
            <input
              type="url"
              placeholder="Paste your long URL here"
              value={longUrl}
              onChange={(e) => setLongUrl(e.target.value)}
              required
            />
          </div>

          {/* NEW: Toggle button for advanced options */}
          <button
            type="button"
            className="advanced-options-toggle"
            onClick={() => setShowAdvancedOptions(!showAdvancedOptions)}
          >
            {showAdvancedOptions ? 'Hide Advanced Options' : 'Advanced Options...'}
          </button>

          {/* NEW: Conditionally rendered container for optional inputs */}
          {showAdvancedOptions && (
            <div className="advanced-options-container">
              <div className="input-group">
                <div className="custom-alias-wrapper">
                  <input
                    type="text"
                    placeholder="alias name"
                    value={customAlias}
                    onChange={handleCustomAliasChange}
                  />
                </div>
                <div className="custom-alias-wrapper">
                  <input
                    type="password"
                    placeholder="Password "
                    value={linkPassword}
                    onChange={(e) => setLinkPassword(e.target.value)}
                  />
                </div>
                <div className="custom-alias-wrapper">
                  <input
                    type="datetime-local"
                    title="Set an expiration date"
                    value={expirationDate}
                    onChange={(e) => setExpirationDate(e.target.value)}
                  />
                </div>
              </div>
            </div>
          )}

          <button type="submit" disabled={loading} className="submit-button">
            {loading ? 'Shortening...' : 'SHORTEN URL'}
          </button>
        </form>

        {shortUrl && (
          <div className="result">
            <p>Your shortened URL:</p>
            <a href={shortUrl} target="_blank" rel="noopener noreferrer">
              {shortUrl}
            </a>
          </div>
        )}
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}

export default App;
