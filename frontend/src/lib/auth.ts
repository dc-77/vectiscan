const TOKEN_KEY = 'vectiscan_token';

export interface UserInfo {
  id: string;
  email: string;
  role: 'customer' | 'admin';
}

export interface AuthResponse {
  token: string;
  user: UserInfo;
}

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
  // Also clean up old session storage from password gate
  sessionStorage.removeItem('vectiscan_auth');
}

export function isLoggedIn(): boolean {
  return !!getToken();
}

export function getUser(): UserInfo | null {
  const token = getToken();
  if (!token) return null;
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    return {
      id: payload.sub,
      email: payload.email,
      role: payload.role,
    };
  } catch {
    return null;
  }
}

export function isAdmin(): boolean {
  return getUser()?.role === 'admin';
}
