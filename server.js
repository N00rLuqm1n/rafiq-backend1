/**
 * src/apiClient.ts
 * Centralized API client with In-Memory Token management
 */

// Private variable to store the JWT in memory (not localStorage)
let accessToken: string | null = null;

// Point to local server by default for local development/hosting, fallback to Vercel if needed
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5055/api';
// const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'https://rafiq-backend1.vercel.app/api';

/**
 * Updates the in-memory token
 */
export const setMemoryToken = (token: string | null) => {
    accessToken = token;
};

/**
 * Generic request helper
 */
async function request(path: string, options: RequestInit = {}) {
    const url = `${API_BASE_URL}${path}`;
    const headers = {
        'Content-Type': 'application/json',
        ...options.headers,
    } as any;

    if (accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }

    const response = await fetch(url, { ...options, headers });

    if (!response.ok) {
        let errorMessage = 'Network response was not ok';
        try {
            const errorData = await response.json();
            errorMessage = errorData.error || errorMessage;
        } catch (e) {
            // Silently fail parsing error JSON
        }
        
        if (response.status === 401 || response.status === 403) {
            setMemoryToken(null); // Clear token on auth error
        }
        
        throw new Error(errorMessage);
    }

    return response.json();
}

export const apiClient = {
    get: (path: string) => request(path, { method: 'GET' }),
    post: (path: string, body: any) => request(path, { method: 'POST', body: JSON.stringify(body) }),
    put: (path: string, body: any) => request(path, { method: 'PUT', body: JSON.stringify(body) }),
    delete: (path: string) => request(path, { method: 'DELETE' }),
};
