// API Configuration
const isDevelopment = typeof window !== 'undefined' && 
  (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1');

const PRODUCTION_API_URL = 'https://threat-intel-integrator.onrender.com';
const DEVELOPMENT_API_URL = 'http://127.0.0.1:8000';

export const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 
  (isDevelopment ? DEVELOPMENT_API_URL : PRODUCTION_API_URL);

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
