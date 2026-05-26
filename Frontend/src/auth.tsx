import { createContext, ReactNode, useCallback, useContext, useMemo } from "react";
import { InteractionRequiredAuthError, InteractionStatus } from "@azure/msal-browser";
import { useAccount, useMsal } from "@azure/msal-react";
import { getPatchForgeConfig } from "./api";

export type PatchForgeAuthStatus = "loading" | "authenticated" | "unauthenticated";

export type PatchForgeAuthSession = {
  status: PatchForgeAuthStatus;
  accountName: string | null;
  roles: string[];
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
  getAccessToken: () => Promise<string>;
};

const defaultSession: PatchForgeAuthSession = {
  status: "unauthenticated",
  accountName: null,
  roles: [],
  signIn: async () => undefined,
  signOut: async () => undefined,
  getAccessToken: async () => {
    throw new Error("PatchForge sign-in is required.");
  }
};

export const PatchForgeAuthContext = createContext<PatchForgeAuthSession>(defaultSession);

export function usePatchForgeAuth(): PatchForgeAuthSession {
  return useContext(PatchForgeAuthContext);
}

export function MsalPatchForgeAuthProvider({ children }: { children: ReactNode }) {
  const { instance, accounts, inProgress } = useMsal();
  const account = useAccount(accounts[0] || null);
  const config = getPatchForgeConfig();
  const loginRequest = useMemo(() => ({ scopes: [config.apiScope] }), [config.apiScope]);
  const status: PatchForgeAuthStatus = inProgress !== InteractionStatus.None
    ? "loading"
    : account
      ? "authenticated"
      : "unauthenticated";

  const signIn = useCallback(async () => {
    await instance.loginRedirect(loginRequest);
  }, [instance, loginRequest]);

  const signOut = useCallback(async () => {
    await instance.logoutRedirect({
      account: account || undefined,
      postLogoutRedirectUri: window.location.origin
    });
  }, [account, instance]);

  const getAccessToken = useCallback(async () => {
    if (!account) {
      throw new Error("PatchForge sign-in is required.");
    }
    try {
      const response = await instance.acquireTokenSilent({
        ...loginRequest,
        account
      });
      return response.accessToken;
    } catch (error) {
      if (error instanceof InteractionRequiredAuthError) {
        await instance.acquireTokenRedirect({
          ...loginRequest,
          account
        });
      }
      throw error;
    }
  }, [account, instance, loginRequest]);

  const session = useMemo<PatchForgeAuthSession>(() => ({
    status,
    accountName: account?.username || account?.name || null,
    roles: normalizeRoles(account?.idTokenClaims?.roles),
    signIn,
    signOut,
    getAccessToken
  }), [account, getAccessToken, signIn, signOut, status]);

  return (
    <PatchForgeAuthContext.Provider value={session}>
      {children}
    </PatchForgeAuthContext.Provider>
  );
}

function normalizeRoles(roles: unknown): string[] {
  if (!roles) {
    return [];
  }
  if (Array.isArray(roles)) {
    return roles.map((role) => String(role));
  }
  return String(roles).split(",").map((role) => role.trim()).filter(Boolean);
}
