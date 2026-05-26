import React from "react";
import ReactDOM from "react-dom/client";
import { PublicClientApplication } from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import App from "./App";
import { getPatchForgeConfig } from "./api";
import { MsalPatchForgeAuthProvider } from "./auth";
import "./styles.css";

const config = getPatchForgeConfig();
const msalInstance = new PublicClientApplication({
  auth: {
    clientId: config.clientId,
    authority: `https://login.microsoftonline.com/${config.tenantId}`,
    redirectUri: `${window.location.origin}/auth/callback`,
    postLogoutRedirectUri: window.location.origin
  },
  cache: {
    cacheLocation: "sessionStorage"
  }
});

await msalInstance.initialize();

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MsalProvider instance={msalInstance}>
      <MsalPatchForgeAuthProvider>
        <App />
      </MsalPatchForgeAuthProvider>
    </MsalProvider>
  </React.StrictMode>
);
