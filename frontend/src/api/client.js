import axios from 'axios';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const instance = axios.create({ baseURL: BASE_URL, timeout: 12000 });

instance.interceptors.request.use((config) => {
  const token = localStorage.getItem('cybersentinel_token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export const login = async ({ email, password }) => {
  const body = new URLSearchParams();
  body.append('username', email);
  body.append('password', password);
  const response = await instance.post('/auth/login', body, {
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  });
  return response.data;
};

export const register = (payload) => instance.post('/auth/register', payload).then(res => res.data);

export const getMockLogs = () => instance.get('/logs/mock').then(res => res.data);

export const scanLogs = (logs) => instance.post('/logs/scan', { logs }).then(res => res.data);

export const getThreats = () => instance.get('/threats').then(res => res.data);

export const getStats = () => instance.get('/threats/stats').then(res => res.data);

export const analyzeThreat = (threat) => {
  const id = typeof threat === 'string' ? threat : (threat && threat.id) || '';
  return instance.post(`/analyze/${id}`).then(res => res.data);
};
