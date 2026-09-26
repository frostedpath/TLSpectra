import {
  Capture, CaptureList, Session, SessionList,
  Finding, FindingList, HostList, ScoreData, Policy
} from '../types';

const API_BASE = '/api/v1';
const DEFAULT_TOKEN = 'sms_sec_token_v1';

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem('sms_bearer_token') || DEFAULT_TOKEN;
  return {
    'Authorization': `Bearer ${token}`,
  };
}

export const api = {
  async getHealth(): Promise<{ status: string; version: string; database: string }> {
    const res = await fetch(`${API_BASE}/health`);
    if (!res.ok) throw new Error('Health check failed');
    return res.json();
  },

  async uploadCapture(file: File): Promise<Capture> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/captures`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || 'Failed to upload capture');
    }
    return res.json();
  },

  async loadDemoCapture(demoType: 'corpus' | 'dropzone' = 'corpus'): Promise<Capture> {
    const res = await fetch(`${API_BASE}/captures/demo?demo_type=${demoType}`, {
      method: 'POST',
      headers: getAuthHeaders(),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || 'Failed to load demo capture');
    }
    return res.json();
  },

  async listCaptures(limit: number = 50): Promise<CaptureList> {
    const res = await fetch(`${API_BASE}/captures?limit=${limit}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load captures');
    return res.json();
  },

  async getCapture(id: string): Promise<Capture> {
    const res = await fetch(`${API_BASE}/captures/${id}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error(`Capture ${id} not found`);
    return res.json();
  },

  async deleteCapture(id: string): Promise<void> {
    const res = await fetch(`${API_BASE}/captures/${id}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error(`Failed to delete capture ${id}`);
  },

  async getCaptureScore(id: string): Promise<ScoreData> {
    const res = await fetch(`${API_BASE}/captures/${id}/score`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Score not available yet');
    return res.json();
  },

  async getCaptureSessions(
    id: string,
    filters?: { protocol?: string; starttls_state?: string; limit?: number }
  ): Promise<SessionList> {
    const params = new URLSearchParams();
    if (filters?.protocol) params.append('protocol', filters.protocol);
    if (filters?.starttls_state) params.append('starttls_state', filters.starttls_state);
    if (filters?.limit) params.append('limit', String(filters.limit));

    const res = await fetch(`${API_BASE}/captures/${id}/sessions?${params.toString()}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load sessions');
    return res.json();
  },

  async getCaptureFindings(
    id: string,
    filters?: { severity?: string; category?: string; protocol?: string; limit?: number }
  ): Promise<FindingList> {
    const params = new URLSearchParams();
    if (filters?.severity) params.append('severity', filters.severity);
    if (filters?.category) params.append('category', filters.category);
    if (filters?.protocol) params.append('protocol', filters.protocol);
    if (filters?.limit) params.append('limit', String(filters.limit));

    const res = await fetch(`${API_BASE}/captures/${id}/findings?${params.toString()}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load findings');
    return res.json();
  },

  async getCaptureHosts(id: string): Promise<HostList> {
    const res = await fetch(`${API_BASE}/captures/${id}/hosts`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load hosts');
    return res.json();
  },

  async getReport(id: string, format: 'json' | 'html' | 'pdf'): Promise<any> {
    const res = await fetch(`${API_BASE}/captures/${id}/report?format=${format}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to generate report');
    if (format === 'json') return res.json();
    if (format === 'html') return res.text();
    return res.blob();
  },

  async getSession(id: string): Promise<Session> {
    const res = await fetch(`${API_BASE}/sessions/${id}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error(`Session ${id} not found`);
    return res.json();
  },

  async getSessionScore(id: string): Promise<ScoreData> {
    const res = await fetch(`${API_BASE}/sessions/${id}/score`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Session score not found');
    return res.json();
  },

  async getSessionFindings(id: string): Promise<FindingList> {
    const res = await fetch(`${API_BASE}/sessions/${id}/findings`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load session findings');
    return res.json();
  },

  async getFinding(id: string): Promise<Finding> {
    const res = await fetch(`${API_BASE}/findings/${id}`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error(`Finding ${id} not found`);
    return res.json();
  },

  async updateFindingFeedback(id: string, feedback: string, notes?: string): Promise<void> {
    const res = await fetch(`${API_BASE}/findings/${id}/feedback`, {
      method: 'PATCH',
      headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ feedback, notes }),
    });
    if (!res.ok) throw new Error('Failed to submit analyst feedback');
  },

  async getHostScore(id: string): Promise<ScoreData> {
    const res = await fetch(`${API_BASE}/hosts/${id}/score`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Host score not found');
    return res.json();
  },

  async getPolicy(): Promise<Policy> {
    const res = await fetch(`${API_BASE}/policy`, {
      headers: getAuthHeaders(),
    });
    if (!res.ok) throw new Error('Failed to load policy');
    return res.json();
  },

  async updatePolicy(policy: Policy): Promise<Policy> {
    const res = await fetch(`${API_BASE}/policy`, {
      method: 'PUT',
      headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    if (!res.ok) throw new Error('Failed to update policy');
    return res.json();
  },
};
