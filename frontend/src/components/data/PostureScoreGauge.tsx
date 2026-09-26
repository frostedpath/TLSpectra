import React from 'react';

interface PostureScoreGaugeProps {
  score: number;
  totalFindings: number;
  totalSessions: number;
}

export const PostureScoreGauge: React.FC<PostureScoreGaugeProps> = ({ score, totalFindings, totalSessions }) => {
  const getRating = (s: number) => {
    if (s >= 80) return { label: 'Good Posture', color: 'text-semantic-success', stroke: '#15803D' };
    if (s >= 50) return { label: 'Moderate Risk', color: 'text-semantic-warning', stroke: '#B45309' };
    return { label: 'High Exposure', color: 'text-semantic-error', stroke: '#B91C1C' };
  };

  const rating = getRating(score);
  const circumference = 2 * Math.PI * 42;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className="bg-surface border border-border rounded-lg p-6 flex flex-col items-center justify-center relative shadow-sm">
      <div className="relative w-40 h-40 flex items-center justify-center">
        <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
          {/* Background Track */}
          <circle
            cx="50"
            cy="50"
            r="42"
            stroke="#E2E8F0"
            strokeWidth="10"
            fill="transparent"
          />
          {/* Active Progress */}
          <circle
            cx="50"
            cy="50"
            r="42"
            stroke={rating.stroke}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Center Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-4xl font-bold text-textPrimary tracking-tight">{score}</span>
          <span className="text-[11px] text-muted uppercase font-semibold">out of 100</span>
        </div>
      </div>

      <div className="mt-3 text-center">
        <div className={`text-sm font-bold ${rating.color}`}>{rating.label}</div>
        <div className="text-xs text-muted mt-0.5">
          {totalFindings} findings across {totalSessions} sessions
        </div>
      </div>
    </div>
  );
};
