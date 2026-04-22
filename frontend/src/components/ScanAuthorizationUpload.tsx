'use client';

import { useCallback, useRef, useState } from 'react';
import { uploadAuthorization } from '@/lib/api';

const DOC_TYPES: Array<{ value: string; label: string }> = [
  { value: 'whois_screenshot', label: 'WHOIS-Screenshot' },
  { value: 'signed_authorization', label: 'Unterschriebene Scan-Freigabe' },
  { value: 'email_thread', label: 'E-Mail-Verlauf' },
  { value: 'scan_agreement', label: 'Scan-Vereinbarung (Vertrag)' },
  { value: 'other', label: 'Sonstiges' },
];

const ACCEPTED = 'application/pdf,image/jpeg,image/png';

interface UploadItem {
  id: string;
  file: File;
  progress: number;
  error: string | null;
  done: boolean;
}

interface Props {
  ownerType: 'order' | 'subscription';
  ownerId: string;
  onUploadComplete: () => void;
}

function isAccepted(file: File): boolean {
  return ['application/pdf', 'image/jpeg', 'image/png'].includes(file.type);
}

export default function ScanAuthorizationUpload({ ownerType, ownerId, onUploadComplete }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [docType, setDocType] = useState<string>('signed_authorization');
  const [notes, setNotes] = useState<string>('');
  const [validUntil, setValidUntil] = useState<string>('');
  const [dragOver, setDragOver] = useState(false);
  const [items, setItems] = useState<UploadItem[]>([]);
  const [error, setError] = useState<string | null>(null);

  const startUpload = useCallback(async (files: File[]) => {
    setError(null);
    const rejected = files.filter(f => !isAccepted(f));
    if (rejected.length > 0) {
      setError(`Nicht unterstützt: ${rejected.map(r => r.name).join(', ')}. Nur PDF, JPG, PNG erlaubt.`);
    }
    const accepted = files.filter(isAccepted);
    if (accepted.length === 0) return;

    const newItems: UploadItem[] = accepted.map(f => ({
      id: `${f.name}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      file: f,
      progress: 0,
      error: null,
      done: false,
    }));
    setItems(prev => [...prev, ...newItems]);

    for (const item of newItems) {
      setItems(prev => prev.map(x => x.id === item.id ? { ...x, progress: 10 } : x));
      const res = await uploadAuthorization(ownerType, ownerId, item.file, {
        documentType: docType,
        notes: notes || undefined,
        validUntil: validUntil || undefined,
      });
      if (res.success) {
        setItems(prev => prev.map(x => x.id === item.id ? { ...x, progress: 100, done: true } : x));
      } else {
        setItems(prev => prev.map(x => x.id === item.id ? { ...x, error: res.error || 'Upload fehlgeschlagen', progress: 0 } : x));
      }
    }

    const allOk = newItems.every(it => !it.error);
    if (allOk) onUploadComplete();
  }, [docType, notes, validUntil, ownerType, ownerId, onUploadComplete]);

  const handleDrop = useCallback((e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragOver(false);
    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) startUpload(files);
  }, [startUpload]);

  const handlePick = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files || []);
    if (files.length > 0) startUpload(files);
    if (inputRef.current) inputRef.current.value = '';
  }, [startUpload]);

  return (
    <div className="bg-[#1e293b] rounded-lg border border-gray-800 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-slate-300">Scan-Autorisierungen</h3>
        <span className="text-[10px] text-slate-500">PDF, JPG, PNG &middot; max 20 MB</span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
        <div>
          <label className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Dokumenttyp</label>
          <select
            value={docType}
            onChange={(e) => setDocType(e.target.value)}
            className="w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 outline-none"
          >
            {DOC_TYPES.map(t => (
              <option key={t.value} value={t.value}>{t.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Gültig bis (optional)</label>
          <input
            type="date"
            value={validUntil}
            onChange={(e) => setValidUntil(e.target.value)}
            className="w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 outline-none"
          />
        </div>
        <div className="md:col-span-1">
          <label className="block text-[10px] text-slate-500 uppercase tracking-wider mb-1">Notizen (optional)</label>
          <input
            type="text"
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="z.B. Freigabe durch Geschäftsführung"
            className="w-full bg-[#0f172a] border border-gray-800 rounded-lg px-2 py-1.5 text-xs text-slate-200 focus:border-blue-500 outline-none"
          />
        </div>
      </div>

      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={`rounded-lg border-2 border-dashed p-6 text-center cursor-pointer transition-colors ${
          dragOver
            ? 'border-blue-500 bg-blue-500/10'
            : 'border-gray-700 hover:border-gray-600 bg-[#0f172a]'
        }`}
      >
        <p className="text-sm text-slate-300">Dateien hierher ziehen oder klicken zum Auswählen</p>
        <p className="text-[10px] text-slate-500 mt-1">Mehrere Dateien möglich</p>
        <input
          ref={inputRef}
          type="file"
          accept={ACCEPTED}
          multiple
          onChange={handlePick}
          className="hidden"
        />
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-300 rounded-lg px-3 py-2 text-xs">
          {error}
        </div>
      )}

      {items.length > 0 && (
        <div className="space-y-1.5">
          {items.map(it => (
            <div key={it.id} className="flex items-center gap-2 text-xs">
              <span className="flex-1 truncate text-slate-300">{it.file.name}</span>
              <span className="text-slate-500 font-mono shrink-0">{(it.file.size / 1024).toFixed(0)} KB</span>
              <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden shrink-0">
                <div
                  className={`h-full rounded-full transition-all ${
                    it.error ? 'bg-red-500' : it.done ? 'bg-green-500' : 'bg-blue-500'
                  }`}
                  style={{ width: `${it.error ? 100 : it.progress}%` }}
                />
              </div>
              <span className="shrink-0 w-14 text-right">
                {it.error ? <span className="text-red-400">Fehler</span>
                  : it.done ? <span className="text-green-400">OK</span>
                  : <span className="text-slate-500">{it.progress}%</span>}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
