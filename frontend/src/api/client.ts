import {
  Capture, CaptureList, Session, SessionList,
  Finding, FindingList, HostList, ScoreData, Policy
} from '../types';
import {
  DEFAULT_POLICY, DEMO_CAPTURE, DEMO_SCORE,
  DEMO_HOSTS, DEMO_FINDINGS, DEMO_SESSIONS
} from './demoData';

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
    try {
      const res = await fetch(`${API_BASE}/health`);
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return { status: 'healthy', version: '1.0.0 (Cloud Demo)', database: 'ready' };
  },

  async uploadCapture(file: File): Promise<Capture> {
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch(`${API_BASE}/captures`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: formData,
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || 'Failed to upload capture');
    } catch (e: any) {
      // If backend is not available, simulate successful upload into demo mode
      console.warn('Backend not reachable, simulating upload demo capture:', e);
      return DEMO_CAPTURE;
    }
  },

  async loadDemoCapture(demoType: 'corpus' | 'dropzone' = 'corpus'): Promise<Capture> {
    try {
      const res = await fetch(`${API_BASE}/captures/demo?demo_type=${demoType}`, {
        method: 'POST',
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_CAPTURE;
  },

  async listCaptures(limit: number = 50): Promise<CaptureList> {
    try {
      const res = await fetch(`${API_BASE}/captures?limit=${limit}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        if (data.items && data.items.length > 0) return data;
      }
    } catch (e) {
      // Fallback
    }
    return { items: [DEMO_CAPTURE], total: 1, limit };
  },

  async getCapture(id: string): Promise<Capture> {
    try {
      const res = await fetch(`${API_BASE}/captures/${id}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_CAPTURE;
  },

  async deleteCapture(id: string): Promise<void> {
    try {
      await fetch(`${API_BASE}/captures/${id}`, {
        method: 'DELETE',
        headers: getAuthHeaders(),
      });
    } catch (e) {
      // Fallback
    }
  },

  async getCaptureScore(id: string): Promise<ScoreData> {
    try {
      const res = await fetch(`${API_BASE}/captures/${id}/score`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_SCORE;
  },

  async getCaptureSessions(
    id: string,
    filters?: { protocol?: string; starttls_state?: string; limit?: number }
  ): Promise<SessionList> {
    try {
      const params = new URLSearchParams();
      if (filters?.protocol) params.append('protocol', filters.protocol);
      if (filters?.starttls_state) params.append('starttls_state', filters.starttls_state);
      if (filters?.limit) params.append('limit', String(filters.limit));

      const res = await fetch(`${API_BASE}/captures/${id}/sessions?${params.toString()}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }

    let items = [...DEMO_SESSIONS];
    if (filters?.protocol) items = items.filter(s => s.protocol.toLowerCase() === filters.protocol?.toLowerCase());
    if (filters?.starttls_state) items = items.filter(s => s.starttls_state.toLowerCase() === filters.starttls_state?.toLowerCase());

    return {
      items,
      total: items.length,
      limit: filters?.limit || 50,
      starttls_counts: {
        'UPGRADED_TLS': 3,
        'IMPLICIT_TLS': 1,
        'PLAINTEXT_FALLBACK': 1
      }
    };
  },

  async getCaptureFindings(
    id: string,
    filters?: { severity?: string; category?: string; protocol?: string; limit?: number }
  ): Promise<FindingList> {
    try {
      const params = new URLSearchParams();
      if (filters?.severity) params.append('severity', filters.severity);
      if (filters?.category) params.append('category', filters.category);
      if (filters?.protocol) params.append('protocol', filters.protocol);
      if (filters?.limit) params.append('limit', String(filters.limit));

      const res = await fetch(`${API_BASE}/captures/${id}/findings?${params.toString()}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }

    let items = [...DEMO_FINDINGS];
    if (filters?.severity) items = items.filter(f => f.severity.toLowerCase() === filters.severity?.toLowerCase());
    if (filters?.category) items = items.filter(f => f.category.toLowerCase() === filters.category?.toLowerCase());
    if (filters?.protocol) items = items.filter(f => f.protocol?.toLowerCase() === filters.protocol?.toLowerCase());

    return {
      items,
      total: items.length,
      limit: filters?.limit || 50,
      severity_counts: {
        'CRITICAL': 1,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 0,
        'INFO': 0
      }
    };
  },

  async getCaptureHosts(id: string): Promise<HostList> {
    try {
      const res = await fetch(`${API_BASE}/captures/${id}/hosts`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return { items: DEMO_HOSTS, total: DEMO_HOSTS.length, limit: 50 };
  },

  async getReport(id: string, format: 'json' | 'html' | 'pdf'): Promise<any> {
    try {
      const res = await fetch(`${API_BASE}/captures/${id}/report?format=${format}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) {
        if (format === 'json') return await res.json();
        if (format === 'html') return await res.text();
        return await res.blob();
      }
    } catch (e) {
      // Fallback
    }
    if (format === 'json') return { capture: DEMO_CAPTURE, score: DEMO_SCORE, findings: DEMO_FINDINGS };
    if (format === 'html') return '<html><body><h1>TLSpectra Forensic Report</h1><p>Demo Report</p></body></html>';
    return new Blob(['TLSpectra Demo PDF'], { type: 'application/pdf' });
  },

  async getSession(id: string): Promise<Session> {
    try {
      const res = await fetch(`${API_BASE}/sessions/${id}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_SESSIONS.find(s => s.session_id === id) || DEMO_SESSIONS[0];
  },

  async getSessionScore(id: string): Promise<ScoreData> {
    try {
      const res = await fetch(`${API_BASE}/sessions/${id}/score`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_SCORE;
  },

  async getSessionFindings(id: string): Promise<FindingList> {
    try {
      const res = await fetch(`${API_BASE}/sessions/${id}/findings`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    const items = DEMO_FINDINGS.filter(f => f.session_id === id);
    return { items: items.length > 0 ? items : DEMO_FINDINGS.slice(0, 2), total: items.length || 2, limit: 50 };
  },

  async getFinding(id: string): Promise<Finding> {
    try {
      const res = await fetch(`${API_BASE}/findings/${id}`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_FINDINGS.find(f => f.finding_id === id) || DEMO_FINDINGS[0];
  },

  async updateFindingFeedback(id: string, feedback: string, notes?: string): Promise<void> {
    try {
      await fetch(`${API_BASE}/findings/${id}/feedback`, {
        method: 'PATCH',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ feedback, notes }),
      });
    } catch (e) {
      // Fallback
    }
  },

  async getHostScore(id: string): Promise<ScoreData> {
    try {
      const res = await fetch(`${API_BASE}/hosts/${id}/score`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEMO_SCORE;
  },

  async getPolicy(): Promise<Policy> {
    try {
      const res = await fetch(`${API_BASE}/policy`, {
        headers: getAuthHeaders(),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return DEFAULT_POLICY;
  },

  async updatePolicy(policy: Policy): Promise<Policy> {
    try {
      const res = await fetch(`${API_BASE}/policy`, {
        method: 'PUT',
        headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify(policy),
      });
      if (res.ok) return await res.json();
    } catch (e) {
      // Fallback
    }
    return policy;
  },
};
