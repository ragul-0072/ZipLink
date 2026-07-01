import React, { useState, useEffect, useLayoutEffect } from 'react';

// --- Modern SVG Icons ---
// We define these as components for easy reuse and clean code
const IconCopy = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
  </svg>
);

const IconQR = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <rect x="3" y="3" width="7" height="7"></rect>
    <rect x="14" y="3" width="7" height="7"></rect>
    <rect x="3" y="14" width="7" height="7"></rect>
    <line x1="14" y1="14" x2="14.01" y2="14"></line><line x1="17" y1="14" x2="17.01" y2="14"></line><line x1="20" y1="14" x2="20.01" y2="14"></line><line x1="14" y1="17" x2="14.01" y2="17"></line><line x1="17" y1="17" x2="17.01" y2="17"></line><line x1="20" y1="17" x2="20.01" y2="17"></line><line x1="14" y1="20" x2="14.01" y2="20"></line><line x1="17" y1="20" x2="17.01" y2="20"></line><line x1="20" y1="20" x2="20.01" y2="20"></line>
  </svg>
);

const IconDelete = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="3 6 5 6 21 6"></polyline>
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path>
    <line x1="10" y1="11" x2="10" y2="17"></line><line x1="14" y1="11" x2="14" y2="17"></line>
  </svg>
);
// --- End of Icons ---

// --- NEW: Viewport Hook ---
// This simple hook detects the screen width
const useViewport = () => {
  const [width, setWidth] = useState(window.innerWidth);

  useLayoutEffect(() => {
    const handleResize = () => setWidth(window.innerWidth);
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return { width };
};
// --- End of Viewport Hook ---


const Dashboard = ({ currentUser, handleLogout, setCurrentView }) => {
  const [links, setLinks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [deleteStatus, setDeleteStatus] = useState({});
  const [qrModal, setQrModal] = useState({ visible: false, url: '', code: '' });
  const [confirmDeleteId, setConfirmDeleteId] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');
  
  // NEW: Get viewport width
  const { width } = useViewport();
  const isMobile = width < 1024; // We'll use the same 1024px breakpoint as CSS

  // --- Utility Functions ---
  const formatLinkDate = (dateStr) => {
    if (!dateStr) return 'Never';
    const dateObj = new Date(dateStr);
    if (isNaN(dateObj.getTime())) return '—';
    return dateObj.toLocaleString('en-GB', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit',
    });
  };

  // --- Data Fetching ---
  const fetchLinks = async () => {
    if (!currentUser || !currentUser.uid) {
      setLoading(false);
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const userId = currentUser.uid;
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/links/${userId}`);
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to fetch links');
      }
      const data = await response.json();
      setLinks(data.links);
    } catch (err) {
      console.error("Dashboard Fetch Error:", err);
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLinks();
  }, [currentUser]);

  // --- Event Handlers ---
  const handleDelete = async (id, shortCode) => {
    setConfirmDeleteId(null);
    setDeleteStatus(prev => ({ ...prev, [id]: true }));
    setError(null);
    try {
      const response = await fetch(`${import.meta.env.VITE_API_BASE_URL}/api/links/${id}`, {
        method: 'DELETE',
      });
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to delete link');
      }
      setLinks(prevLinks => prevLinks.filter(link => link.id !== id));
    } catch (err) {
      console.error("Delete Error:", err);
      setError(err.message);
    } finally {
      setDeleteStatus(prev => ({ ...prev, [id]: false }));
    }
  };

  const copyLink = (shortUrl, e) => {
    try {
      navigator.clipboard.writeText(shortUrl).then(() => {
        const el = e.currentTarget;
        const originalText = el.innerHTML;
        el.innerHTML = 'Copied!';
        el.classList.add('copied');
        setTimeout(() => {
          el.innerHTML = originalText;
          el.classList.remove('copied');
        }, 1500);
      });
    } catch (err) {
      // Fallback
      try {
        const el = document.createElement('textarea');
        el.value = shortUrl;
        document.body.appendChild(el);
        el.select();
        document.execCommand('copy');
        document.body.removeChild(el);
        const copyButton = e.currentTarget;
        const originalText = copyButton.innerHTML;
        copyButton.innerHTML = 'Copied!';
        copyButton.classList.add('copied');
        setTimeout(() => {
          copyButton.innerHTML = originalText;
          copyButton.classList.remove('copied');
        }, 1500);
      } catch (execErr) {
        prompt('Copy the link manually:', shortUrl);
      }
    }
  };

  // --- QR Code Logic (FIXED) ---
  const generateQr = (url) => {
    const qrDiv = document.getElementById('qrcode');
    if (qrDiv) { // Safety check
      qrDiv.innerHTML = '';
      new window.QRCode(qrDiv, {
        text: url, width: 256, height: 256,
        colorDark: "#121212", colorLight: "#ffffff",
        correctLevel: window.QRCode.CorrectLevel.H
      });
    } else {
      console.error("Could not find div with id 'qrcode'");
    }
  };

  // MODIFIED: showQrCode just sets the state
  const showQrCode = (url, code) => {
    setQrModal({ visible: true, url, code });
    // We no longer call generateQr() here
  };

  // NEW: useEffect hook to run AFTER render
  useEffect(() => {
    if (qrModal.visible) {
      // Now we know the modal (and div#qrcode) exists
      if (window.QRCode) {
        generateQr(qrModal.url);
      } else {
        const script = document.createElement('script');
        script.src = "https://cdn.rawgit.com/davidshimjs/qrcodejs/gh-pages/qrcode.min.js";
        script.onload = () => generateQr(qrModal.url);
        document.body.appendChild(script);
      }
    }
  }, [qrModal.visible, qrModal.url]); // Re-run if the modal becomes visible or URL changes
  // --- End QR Code Fix ---


  // --- Derived State ---
  const filteredLinks = links.filter(link =>
    (link.long_url && link.long_url.toLowerCase().includes(searchTerm.toLowerCase())) ||
    (link.short_code && link.short_code.toLowerCase().includes(searchTerm.toLowerCase()))
  );
  const totalLinks = links.length;
  const totalClicks = links.reduce((acc, link) => acc + (link.clicks || 0), 0);

  // --- Render Functions ---
  const dashboardContent = () => {
    if (loading) {
      return <p className="dashboard-message">Loading your links...</p>;
    }
    if (error) {
      return <p className="error dashboard-message">Error: {error}</p>;
    }
    if (links.length === 0) {
      return (
        <p className="dashboard-message">
          You haven't created any links yet.
        </p>
      );
    }
    if (filteredLinks.length === 0) {
      return (
        <p className="dashboard-message">
          No links found matching your search.
        </p>
      );
    }
    
    // --- NEW: Conditional Rendering ---
    // Pass all props down to the view components
    const viewProps = {
      links: filteredLinks,
      confirmDeleteId,
      setConfirmDeleteId,
      handleDelete,
      deleteStatus,
      copyLink,
      showQrCode,
      formatLinkDate
    };

    return isMobile ? <DashboardMobileView {...viewProps} /> : <DashboardDesktopView {...viewProps} />;
  };

  return (
    <>
      <div className="container main-app dashboard-view">
        <div className="app-header">
          <img src="/ZipLink_logo.jpg" alt="ZipLink Logo" className="main-app-logo" />
          <div className="user-info">
            <button className="view-switch-button" onClick={() => setCurrentView('shortener')}>
              Shortener
            </button>
            <button className="logout-button" onClick={handleLogout}>Log Out</button>
          </div>
        </div>
        <h2 className="dashboard-title">Your Link Dashboard</h2>
        <div className="dashboard-stats">
          <div className="stat-card">
            <h3>Total Links</h3>
            <span>{loading ? '...' : totalLinks}</span>
          </div>
          <div className="stat-card">
            <h3>Total Clicks</h3>
            <span>{loading ? '...' : totalClicks}</span>
          </div>
        </div>
        {!error && (links.length > 0 || loading) && (
          <div className="dashboard-header-controls">
            <input 
              type="text"
              className="search-bar"
              placeholder="Filter links by URL or code..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
            />
            <button 
              className="create-link-button-header" 
              onClick={() => setCurrentView('shortener')}
            >
              Create New Link
            </button>
          </div>
        )}
        
        {dashboardContent()}
      </div>

      {qrModal.visible && (
        <div className="qr-modal-backdrop">
          <div className="qr-modal-content container">
            <h2 className="qr-title">QR Code for /{qrModal.code}</h2>
            <p className="qr-url">{qrModal.url}</p>
            <div id="qrcode" className="qrcode-display"></div>
            <button
              className="qr-close-button"
              onClick={() => setQrModal({ visible: false, url: '', code: '' })}
            >
              Close
            </button>
          </div>
        </div>
      )}
    </>
  );
};

// --- NEW: Desktop View Component ---
// This contains your original, unchanged table layout
const DashboardDesktopView = ({ links, confirmDeleteId, setConfirmDeleteId, handleDelete, deleteStatus, copyLink, showQrCode, formatLinkDate }) => (
  <div className="links-table-container">
    <table>
      <thead>
        <tr>
          <th>Short Link</th>
          <th>Original URL</th>
          <th>Clicks</th>
          <th>Created</th>
          <th>Expires</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {links.map((link) => (
          <tr key={link.id}>
            <td className="short-link-cell">
              <a href={link.short_url} target="_blank" rel="noopener noreferrer">
                {link.short_code}
              </a>
            </td>
            <td className="long-url-cell">
              <span title={link.long_url}>{link.long_url}</span>
            </td>
            <td className="clicks-cell">{link.clicks}</td>
            <td>{formatLinkDate(link.created_at)}</td>
            <td>{formatLinkDate(link.expires_at)}</td>
            <td className="action-cell">
              {confirmDeleteId === link.id ? (
                <div className="delete-confirm-box">
                  <span>Confirm?</span>
                  <div>
                    <button className="confirm" onClick={() => handleDelete(link.id, link.short_code)}>Yes</button>
                    <button className="cancel" onClick={() => setConfirmDeleteId(null)}>No</button>
                  </div>
                </div>
              ) : (
                <>
                  <button className="icon-button copy-button" title="Copy Link" onClick={(e) => copyLink(link.short_url, e)}>
                    <IconCopy />
                  </button>
                  <button className="icon-button qr-button" title="Generate QR Code" onClick={() => showQrCode(link.short_url, link.short_code)}>
                    <IconQR />
                  </button>
                  <button className="icon-button delete-button" title="Delete Link" onClick={() => setConfirmDeleteId(link.id)} disabled={deleteStatus[link.id]}>
                    {deleteStatus[link.id] ? '...' : <IconDelete />}
                  </button>
                </>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  </div>
);

// --- NEW: Mobile View Component ---
// This is a new, custom DIV-based layout for mobile
const DashboardMobileView = ({ links, confirmDeleteId, setConfirmDeleteId, handleDelete, deleteStatus, copyLink, showQrCode, formatLinkDate }) => (
  <div className="mobile-link-list">
    {links.map((link) => (
      <div key={link.id} className="mobile-link-card">
        
        <div className="card-section-main">
          <div className="card-short-link">
            <a href={link.short_url} target="_blank" rel="noopener noreferrer">
              {link.short_code}
            </a>
          </div>
          <div className="card-long-url" title={link.long_url}>
            {link.long_url}
          </div>
        </div>

        <div className="card-section-details">
          <div className="card-detail-item">
            <span className="card-label">Clicks</span>
            <span className="card-value clicks-cell">{link.clicks}</span>
          </div>
          <div className="card-detail-item">
            <span className="card-label">Created</span>
            <span className="card-value">{formatLinkDate(link.created_at)}</span>
          </div>
          <div className="card-detail-item">
            <span className="card-label">Expires</span>
            <span className="card-value">{formatLinkDate(link.expires_at)}</span>
          </div>
        </div>

        <div className="card-section-actions">
          {confirmDeleteId === link.id ? (
            <div className="delete-confirm-box">
              <span>Confirm Delete?</span>
              <div>
                <button className="confirm" onClick={() => handleDelete(link.id, link.short_code)}>Yes</button>
                <button className="cancel" onClick={() => setConfirmDeleteId(null)}>No</button>
              </div>
            </div>
          ) : (
            <>
              <button className="icon-button copy-button" title="Copy Link" onClick={(e) => copyLink(link.short_url, e)}>
                <IconCopy /> Copy
              </button>
              <button className="icon-button qr-button" title="Generate QR Code" onClick={() => showQrCode(link.short_url, link.short_code)}>
                <IconQR /> QR
              </button>
              <button className="icon-button delete-button" title="Delete Link" onClick={() => setConfirmDeleteId(link.id)} disabled={deleteStatus[link.id]}>
                {deleteStatus[link.id] ? '...' : <><IconDelete /> Delete</>}
              </button>
            </>
          )}
        </div>
      </div>
    ))}
  </div>
);

export default Dashboard;

