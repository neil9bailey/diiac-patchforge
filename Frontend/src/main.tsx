import React from "react";
import ReactDOM from "react-dom/client";
import { PublicClientApplication } from "@azure/msal-browser";
import { MsalProvider } from "@azure/msal-react";
import App from "./App";
import { getPatchForgeConfig } from "./api";
import { MsalPatchForgeAuthProvider, PatchForgeAuthSession } from "./auth";
import "./styles.css";

const previewParams = new URLSearchParams(window.location.search);
const localPreviewEnabled = import.meta.env.DEV && previewParams.get("preview") === "1";
const allowedPreviewRoles = [
  "PatchForge.Reader",
  "PatchForge.TriageAnalyst",
  "PatchForge.SecurityLead",
  "PatchForge.CABApprover",
  "PatchForge.Auditor",
  "PatchForge.Admin"
] as const;
const requestedPreviewRole = previewParams.get("previewRole");
const localPreviewRole = localPreviewEnabled && allowedPreviewRoles.includes(requestedPreviewRole as typeof allowedPreviewRoles[number])
  ? requestedPreviewRole as typeof allowedPreviewRoles[number]
  : "PatchForge.Admin";
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
  roles: [localPreviewRole],
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
