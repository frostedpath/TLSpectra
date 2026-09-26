import React, { useState, useRef } from 'react';
import { UploadCloud, File, AlertCircle } from 'lucide-react';

interface FileDropzoneProps {
  onFileSelected: (file: File) => void;
  disabled?: boolean;
}

export const FileDropzone: React.FC<FileDropzoneProps> = ({ onFileSelected, disabled }) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const validateAndSelect = (file: File) => {
    setError(null);
    if (!file.name.match(/\.(pcap|pcapng|cap)$/i)) {
      setError('Invalid file format. Please provide a standard .pcap or .pcapng packet capture.');
      return;
    }
    if (file.size > 2 * 1024 * 1024 * 1024) {
      setError('File size exceeds the 2 GB capture capacity limit.');
      return;
    }
    onFileSelected(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    if (disabled) return;
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      validateAndSelect(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="space-y-3">
      <div
        onDragOver={(e) => { e.preventDefault(); setIsDragOver(true); }}
        onDragLeave={() => setIsDragOver(false)}
        onDrop={handleDrop}
        onClick={() => !disabled && inputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all flex flex-col items-center justify-center ${
          isDragOver
            ? 'border-primary bg-primary/5 scale-[1.01]'
            : 'border-border bg-surface hover:bg-elevated/70'
        } ${disabled ? 'opacity-50 cursor-not-allowed' : ''}`}
        tabIndex={0}
        role="button"
        aria-label="Upload capture file dropzone"
        onKeyDown={(e) => {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            inputRef.current?.click();
          }
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept=".pcap,.pcapng,.cap"
          className="hidden"
          onChange={(e) => {
            if (e.target.files && e.target.files.length > 0) {
              validateAndSelect(e.target.files[0]);
            }
          }}
          disabled={disabled}
        />

        <div className="w-12 h-12 rounded-full bg-primary/10 text-primary flex items-center justify-center mb-3">
          <UploadCloud className="w-6 h-6" />
        </div>

        <div className="text-sm font-semibold text-textPrimary">
          Drop your email PCAP or PCAPNG capture here
        </div>
        <div className="text-xs text-muted mt-1 max-w-sm">
          Supports SMTP, IMAP, POP3, and TLS handshakes up to 2 GB. Local-first passive processing.
        </div>
      </div>

      {error && (
        <div className="p-3 bg-red-50 border border-red-200 rounded-md text-xs text-semantic-error flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}
    </div>
  );
};
