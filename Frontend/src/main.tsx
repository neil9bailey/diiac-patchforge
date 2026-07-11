import React from "react";
import ReactDOM from "react-dom/client";
import { PublicClientApplication } from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import App from "./App";
import { getPatchForgeConfig } from "./api";
import { MsalPatchForgeAuthProvider, PatchForgeAuthSession } from "./auth";
import "./styles.css";

const localPreviewEnabled = import.meta.env.DEV && new URLSearchParams(window.location.search).get("preview") === "1";
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

const localPreviewSession: PatchForgeAuthSession = {
  status: "authenticated",
  accountName: "preview.admin@diiac.io",
  roles: ["PatchForge.Admin"],
  signIn: async () => undefined,
  signOut: async () => {
    window.location.assign(window.location.pathname);
  },
  getAccessToken: async () => "local-preview"
};

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <MsalProvider instance={msalInstance}>
      <MsalPatchForgeAuthProvider>
        <App auth={localPreviewEnabled ? localPreviewSession : undefined} />
      </MsalPatchForgeAuthProvider>
    </MsalProvider>
  </React.StrictMode>
);
