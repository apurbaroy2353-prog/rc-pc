import { initializeApp, getApps, getApp } from 'firebase/app';
import {
  getAuth,
  signInWithPopup,
  GoogleAuthProvider,
  onAuthStateChanged,
  User,
  signOut,
} from 'firebase/auth';

import firebaseConfig from '../../firebase-applet-config.json';

// Single Firebase App instance
export const app = getApps().length
  ? getApp()
  : initializeApp(firebaseConfig);

export const auth = getAuth(app);

// Google Drive read-only permission
export const SCOPES = [
  'https://www.googleapis.com/auth/drive.readonly',
];

const provider = new GoogleAuthProvider();

// Add Google Drive scope
SCOPES.forEach((scope) => {
  provider.addScope(scope);
});

// Always show Google account selection
provider.setCustomParameters({
  prompt: 'select_account',
});

// Prevent duplicate sign-in handling
let isSigningIn = false;

// Temporary access-token cache
let cachedAccessToken: string | null = null;

export const initAuth = (
  onAuthSuccess?: (user: User, token: string) => void,
  onAuthFailure?: () => void
) => {
  return onAuthStateChanged(auth, async (user: User | null) => {
    if (user) {
      if (cachedAccessToken) {
        onAuthSuccess?.(user, cachedAccessToken);
      } else if (!isSigningIn) {
        onAuthFailure?.();
      }
    } else {
      cachedAccessToken = null;
      onAuthFailure?.();
    }
  });
};

export const googleSignIn = async (): Promise<{
  user: User;
  accessToken: string;
} | null> => {
  try {
    isSigningIn = true;

    const result = await signInWithPopup(auth, provider);

    const credential =
      GoogleAuthProvider.credentialFromResult(result);

    if (!credential?.accessToken) {
      throw new Error(
        'Failed to get Google Drive access token from Firebase Auth'
      );
    }

    cachedAccessToken = credential.accessToken;

    return {
      user: result.user,
      accessToken: credential.accessToken,
    };
  } catch (error) {
    console.error('Google Sign In error:', error);
    throw error;
  } finally {
    isSigningIn = false;
  }
};

export const getAccessToken = (): string | null => {
  return cachedAccessToken;
};

export const setAccessToken = (token: string | null): void => {
  cachedAccessToken = token;
};

export const logout = async (): Promise<void> => {
  await signOut(auth);
  cachedAccessToken = null;
};
