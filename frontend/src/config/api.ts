// API configuration based on environment
export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 
  (typeof window !== 'undefined' && window.location.hostname === 'localhost'
    ? 'http://127.0.0.1:8000'
    : 'https://your-backend-url.onrender.com'); // Update after backend deployment

export const API_ENDPOINTS = {
  analyze: `${API_BASE_URL}/analyze`,
  sources: `${API_BASE_URL}/sources`,
  indicators: `${API_BASE_URL}/indicators`,
  search: `${API_BASE_URL}/search`,
  graph: (indicator: string) => `${API_BASE_URL}/graph/${indicator}`,
  mitre: `${API_BASE_URL}/mitre/statistics`,
  health: `${API_BASE_URL}/health`,
  root: API_BASE_URL,
};

export default API_BASE_URL;
