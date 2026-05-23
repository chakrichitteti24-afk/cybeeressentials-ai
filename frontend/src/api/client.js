import axios from 'axios';

const BASE_URL = 'http://localhost:8000';
const instance = axios.create({ baseURL: BASE_URL, timeout: 8000 });

export const getMockLogs = () => instance.get('/logs/mock').then(res => res.data);

export const scanLogs = (logs) => instance.post('/logs/scan', { logs }).then(res => res.data);

export const getThreats = () => instance.get('/threats').then(res => res.data);

export const getStats = () => instance.get('/threats/stats').then(res => res.data);

export const analyzeThreat = (threat) => {
  const id = typeof threat === 'string' ? threat : (threat && threat.id) || '';
  return instance.post(`/analyze/${id}`).then(res => res.data);
};
