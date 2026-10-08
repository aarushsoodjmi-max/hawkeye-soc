import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import App from './App.tsx';
import './index.css';
import { AuthProvider } from './context/AuthContext';
import { SocProvider } from './context/SocContext';
import { installAssetFallbacks } from './assetFallback';

installAssetFallbacks();

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <AuthProvider>
      <SocProvider>
        <App />
      </SocProvider>
    </AuthProvider>
  </StrictMode>,
);
