import React, { useState, useRef } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  Upload,
  Code,
  FileText,
  AlertCircle,
  CheckCircle2,
  X,
  Play,
  RotateCcw,
  Sparkles,
  Loader2,
  Shield,
  FileCode,
  ChevronRight,
  Info
} from 'lucide-react';
import { DEMO_RAW_EMAIL } from './mockDemoEmail';

type InputMode = 'upload' | 'paste';

type AnalysisStage = {
  id: string;
  name: string;
  detail: string;
  status: 'pending' | 'active' | 'completed' | 'error';
};

type ErrorType = 'invalid_file' | 'unsupported_file' | 'empty_input' | 'parsing_failure' | 'backend_failure' | null;

export const AnalyzeEmail: React.FC = () => {
  const navigate = useNavigate();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Input states
  const [activeTab, setActiveTab] = useState<InputMode>('upload');
  const [rawText, setRawText] = useState<string>('');
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState<boolean>(false);

  // Error state
  const [errorType, setErrorType] = useState<ErrorType>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // Processing state
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [analysisComplete, setAnalysisComplete] = useState<boolean>(false);
  const [stages, setStages] = useState<AnalysisStage[]>([
    { id: 'parsing', name: 'Parsing email', detail: 'Parsing MIME structures, headers, and body parts...', status: 'pending' },
    { id: 'auth', name: 'Checking authentication', detail: 'Evaluating SPF, DKIM, DMARC, and ARC records...', status: 'pending' },
    { id: 'iocs', name: 'Extracting indicators', detail: 'Identifying IPv4/v6 addresses, domains, URLs, and file hashes...', status: 'pending' },
    { id: 'content', name: 'Analyzing content', detail: 'Performing NLP classification, intent detection, and urgent phrasing analysis...', status: 'pending' },
    { id: 'infra', name: 'Building infrastructure intelligence', detail: 'Mapping relay network hops, ASN records, and IP geolocations...', status: 'pending' },
  ]);

  // Demo file helper
  const handleUseDemoEmail = () => {
    setActiveTab('paste');
    setRawText(DEMO_RAW_EMAIL);
    setSelectedFile(null);
    clearErrors();
  };

  // Clear helper
  const handleClear = () => {
    setRawText('');
    setSelectedFile(null);
    clearErrors();
    setIsAnalyzing(false);
    setAnalysisComplete(false);
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const clearErrors = () => {
    setErrorType(null);
    setErrorMessage(null);
  };

  // File dropzone handlers
  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const processFile = (file: File) => {
    clearErrors();
    const fileName = file.name.toLowerCase();
    
    // Check file extension
    if (!fileName.endsWith('.eml')) {
      setErrorType('unsupported_file');
      setErrorMessage(`Unsupported file format "${file.name}". Only .eml files are accepted for forensic analysis.`);
      setSelectedFile(null);
      return;
    }

    // Check size limit (e.g. 25MB)
    if (file.size > 25 * 1024 * 1024) {
      setErrorType('invalid_file');
      setErrorMessage(`File "${file.name}" exceeds the maximum 25MB size limit.`);
      setSelectedFile(null);
      return;
    }

    setSelectedFile(file);
    
    // Read text from file to populate raw view as well
    const reader = new FileReader();
    reader.onload = (e) => {
      const content = e.target?.result as string;
      if (content) {
        setRawText(content);
      }
    };
    reader.onerror = () => {
      setErrorType('parsing_failure');
      setErrorMessage(`Failed to read content from "${file.name}". File may be corrupted or unreadable.`);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  // Form submission handler
  const handleAnalyze = async (forceError?: ErrorType) => {
    clearErrors();
    setAnalysisComplete(false);

    // Manual test error trigger if requested
    if (forceError) {
      triggerError(forceError);
      return;
    }

    // Validation
    if (activeTab === 'upload' && !selectedFile && !rawText.trim()) {
      setErrorType('empty_input');
      setErrorMessage('Please drop or select an .eml file to proceed with analysis.');
      return;
    }

    if (activeTab === 'paste' && !rawText.trim()) {
      setErrorType('empty_input');
      setErrorMessage('Raw email input is empty. Paste RFC-822 email headers and body to analyze.');
      return;
    }

    // Check for simulated parsing failure keyword in text for testing
    if (rawText.includes('FORCE_PARSING_FAILURE')) {
      triggerError('parsing_failure');
      return;
    }

    if (rawText.includes('FORCE_BACKEND_FAILURE')) {
      triggerError('backend_failure');
      return;
    }

    // Check minimal MIME validity if text provided
    if (rawText.trim() && !rawText.includes(':') && rawText.trim().length < 20) {
      setErrorType('parsing_failure');
      setErrorMessage('Email parsing failure: Input does not contain valid RFC-822 header fields (Key: Value).');
      return;
    }

    // Start processing simulation
    setIsAnalyzing(true);

    // Reset stages
    setStages([
      { id: 'parsing', name: 'Parsing email', detail: 'Parsing MIME structures, headers, and body parts...', status: 'active' },
      { id: 'auth', name: 'Checking authentication', detail: 'Evaluating SPF, DKIM, DMARC, and ARC records...', status: 'pending' },
      { id: 'iocs', name: 'Extracting indicators', detail: 'Identifying IPv4/v6 addresses, domains, URLs, and file hashes...', status: 'pending' },
      { id: 'content', name: 'Analyzing content', detail: 'Performing NLP classification, intent detection, and urgent phrasing analysis...', status: 'pending' },
      { id: 'infra', name: 'Building infrastructure intelligence', detail: 'Mapping relay network hops, ASN records, and IP geolocations...', status: 'pending' },
    ]);

    try {
      const formData = new FormData();
      if (activeTab === 'upload' && selectedFile) {
        formData.append('file', selectedFile);
      } else if (activeTab === 'paste' && rawText) {
        formData.append('raw_text', rawText);
      }

      const response = await fetch('/api/v1/emails/analyze', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        let errMessage = 'Analysis failed due to server error.';
        try {
            const errorData = await response.json();
            errMessage = errorData.detail || errMessage;
        } catch(e) {}
        throw new Error(errMessage);
      }

      const data = await response.json();

      // Stage 1 -> 2
      setTimeout(() => {
        setStages(prev => prev.map((s, idx) => 
          idx === 0 ? { ...s, status: 'completed' } : idx === 1 ? { ...s, status: 'active' } : s
        ));
      }, 300);

      // Stage 2 -> 3
      setTimeout(() => {
        setStages(prev => prev.map((s, idx) => 
          idx === 1 ? { ...s, status: 'completed' } : idx === 2 ? { ...s, status: 'active' } : s
        ));
      }, 600);

      // Stage 3 -> 4
      setTimeout(() => {
        setStages(prev => prev.map((s, idx) => 
          idx === 2 ? { ...s, status: 'completed' } : idx === 3 ? { ...s, status: 'active' } : s
        ));
      }, 900);

      // Stage 4 -> 5
      setTimeout(() => {
        setStages(prev => prev.map((s, idx) => 
          idx === 3 ? { ...s, status: 'completed' } : idx === 4 ? { ...s, status: 'active' } : s
        ));
      }, 1200);

      // Stage 5 completed
      setTimeout(() => {
        setStages(prev => prev.map(s => ({ ...s, status: 'completed' })));
        setIsAnalyzing(false);
        setAnalysisComplete(true);
        if (data && data.id) {
          navigate(`/investigations/${data.id}`);
        }
      }, 1500);

    } catch (err: any) {
      console.error(err);
      triggerError('backend_failure');
      setErrorMessage(err.message || 'An error occurred during analysis.');
    }
  };

  // Helper to test error states directly
  const triggerError = (type: ErrorType) => {
    setErrorType(type);
    setIsAnalyzing(false);
    setAnalysisComplete(false);
    switch (type) {
      case 'invalid_file':
        setErrorMessage('Invalid file: The file corrupted during read or has invalid MIME boundaries.');
        break;
      case 'unsupported_file':
        setErrorMessage('Unsupported file: Only .eml files are supported by the MailTrace AI forensic parser.');
        break;
      case 'empty_input':
        setErrorMessage('Empty submission: No email file or raw header text was provided.');
        break;
      case 'parsing_failure':
        setErrorMessage('Parsing failure: Unable to decode email structure. Headers appear malformed or incomplete.');
        break;
      case 'backend_failure':
        setErrorMessage('Backend error: Threat intelligence service failed to respond (HTTP 503 Service Unavailable).');
        break;
    }
  };

  // Code editor stats
  const lineCount = rawText ? rawText.split('\n').length : 0;
  const byteCount = new Blob([rawText]).size;

  return (
    <div className="space-y-6 max-w-[1200px] mx-auto">
      {/* Navigation Breadcrumb & Header */}
      <div>
        <div className="flex items-center gap-2 text-sm text-slate-500 mb-2 font-medium">
          <Link to="/" className="hover:text-primary transition-colors flex items-center gap-1">
            Dashboard
          </Link>
          <ChevronRight className="w-4 h-4 text-slate-300" />
          <span className="text-slate-800 font-semibold">Analyze Email</span>
        </div>
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-800">Analyze Email</h1>
            <p className="text-sm text-slate-500 mt-1">
              Submit an email for threat detection and forensic analysis.
            </p>
          </div>

          <button
            onClick={handleUseDemoEmail}
            className="flex items-center gap-2 border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 px-3.5 py-1.5 rounded-md text-xs font-semibold shadow-xs transition-colors"
          >
            <Sparkles className="w-3.5 h-3.5 text-primary" />
            Use Demo Email
          </button>
        </div>
      </div>

      {/* Main Analysis Input Card */}
      <div className="bg-white border border-slate-200 rounded-lg shadow-xs overflow-hidden">
        {/* Input Method Selector Tabs */}
        <div className="flex border-b border-slate-200 bg-slate-50/70 px-4 pt-3 gap-2">
          <button
            onClick={() => setActiveTab('upload')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-t-md text-sm font-medium border-b-2 transition-all ${
              activeTab === 'upload'
                ? 'bg-white border-primary text-primary shadow-2xs font-semibold'
                : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100/50'
            }`}
          >
            <Upload className="w-4 h-4" />
            Upload Email (.eml)
          </button>
          <button
            onClick={() => setActiveTab('paste')}
            className={`flex items-center gap-2 px-4 py-2.5 rounded-t-md text-sm font-medium border-b-2 transition-all ${
              activeTab === 'paste'
                ? 'bg-white border-primary text-primary shadow-2xs font-semibold'
                : 'border-transparent text-slate-600 hover:text-slate-900 hover:bg-slate-100/50'
            }`}
          >
            <Code className="w-4 h-4" />
            Paste Raw Email
          </button>
        </div>

        <div className="p-6">
          {/* Error Banner */}
          {errorMessage && (
            <div className="mb-6 bg-red-50 border border-red-200 rounded-md p-4 flex items-start justify-between text-sm text-red-800 animate-in fade-in duration-200">
              <div className="flex items-start gap-3">
                <AlertCircle className="w-5 h-5 text-red-600 shrink-0 mt-0.5" />
                <div>
                  <h4 className="font-semibold text-red-900 flex items-center gap-2">
                    Analysis Submission Error
                    {errorType && (
                      <span className="text-[10px] font-mono font-bold uppercase bg-red-100 text-red-800 px-1.5 py-0.5 rounded border border-red-200">
                        {errorType}
                      </span>
                    )}
                  </h4>
                  <p className="mt-0.5 text-red-700">{errorMessage}</p>
                </div>
              </div>
              <button
                onClick={clearErrors}
                className="text-red-400 hover:text-red-700 p-1 rounded transition-colors"
                title="Dismiss error"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {/* TAB 1: UPLOAD EMAIL (.EML) */}
          {activeTab === 'upload' && (
            <div className="space-y-4">
              <input
                ref={fileInputRef}
                type="file"
                accept=".eml"
                onChange={handleFileSelect}
                className="hidden"
              />

              {!selectedFile ? (
                <div
                  onDragOver={handleDragOver}
                  onDragLeave={handleDragLeave}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className={`border-2 border-dashed rounded-lg p-10 text-center cursor-pointer transition-all ${
                    isDragging
                      ? 'border-primary bg-blue-50/60 scale-[0.99]'
                      : 'border-slate-300 hover:border-slate-400 bg-slate-50/30 hover:bg-slate-50'
                  }`}
                >
                  <div className="w-12 h-12 rounded-full bg-blue-50 text-primary flex items-center justify-center mx-auto mb-3 border border-blue-100">
                    <Upload className="w-6 h-6" />
                  </div>
                  <h3 className="text-base font-semibold text-slate-800">
                    Drop an .eml file here
                  </h3>
                  <p className="text-xs text-slate-500 mt-1 mb-4">
                    Supported format: .eml
                  </p>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      fileInputRef.current?.click();
                    }}
                    className="bg-white border border-slate-300 hover:bg-slate-50 text-slate-700 font-medium px-4 py-2 rounded-md text-sm transition-colors shadow-2xs inline-flex items-center gap-2"
                  >
                    <FileText className="w-4 h-4 text-slate-500" />
                    Choose File
                  </button>
                </div>
              ) : (
                <div className="border border-slate-200 rounded-lg p-5 bg-slate-50/50 flex items-center justify-between">
                  <div className="flex items-center gap-4">
                    <div className="w-10 h-10 rounded-md bg-blue-100 text-primary flex items-center justify-center font-bold text-xs uppercase border border-blue-200">
                      EML
                    </div>
                    <div>
                      <div className="font-semibold text-slate-800 text-sm flex items-center gap-2">
                        {selectedFile.name}
                        <span className="bg-emerald-100 text-emerald-800 text-[10px] font-bold px-2 py-0.5 rounded uppercase">
                          Ready
                        </span>
                      </div>
                      <div className="text-xs text-slate-500 mt-0.5">
                        {(selectedFile.size / 1024).toFixed(1)} KB • RFC-822 Format
                      </div>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <button
                      type="button"
                      onClick={() => fileInputRef.current?.click()}
                      className="text-xs text-slate-600 hover:text-slate-900 font-medium border border-slate-200 bg-white px-3 py-1.5 rounded transition-colors"
                    >
                      Change File
                    </button>
                    <button
                      type="button"
                      onClick={handleClear}
                      className="text-xs text-red-600 hover:text-red-800 font-medium p-1.5 hover:bg-red-50 rounded transition-colors"
                      title="Remove file"
                    >
                      <X className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: PASTE RAW EMAIL */}
          {activeTab === 'paste' && (
            <div className="space-y-3">
              <div className="flex items-center justify-between text-xs text-slate-500 font-medium">
                <span>RFC-822 MIME Payload Editor</span>
                <span>
                  {lineCount} {lineCount === 1 ? 'line' : 'lines'} • {byteCount} bytes
                </span>
              </div>
              <div className="relative border border-slate-200 rounded-md overflow-hidden bg-slate-900 text-slate-100 font-mono text-xs">
                <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex items-center justify-between text-slate-400 text-[11px]">
                  <span className="flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5 text-blue-400" />
                    raw_email_stream.eml
                  </span>
                  <span>UTF-8 Header Encoding</span>
                </div>
                <textarea
                  value={rawText}
                  onChange={(e) => {
                    setRawText(e.target.value);
                    if (errorMessage) clearErrors();
                  }}
                  placeholder={`Received: from mail-server.domain.com ...\nFrom: sender@example.com\nTo: recipient@company.com\nSubject: Sample Phishing Email\n\nEmail body content here...`}
                  rows={14}
                  className="w-full p-4 bg-slate-950 text-slate-200 focus:outline-none focus:ring-1 focus:ring-primary font-mono text-xs leading-relaxed resize-y"
                  spellCheck={false}
                />
              </div>
            </div>
          )}

          {/* Controls & Actions */}
          <div className="mt-6 pt-5 border-t border-slate-100 flex items-center justify-between flex-wrap gap-4">
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => handleAnalyze()}
                disabled={isAnalyzing}
                className="bg-primary hover:bg-primary-hover disabled:bg-slate-300 text-white font-semibold px-5 py-2.5 rounded-md text-sm flex items-center gap-2 transition-colors shadow-2xs cursor-pointer disabled:cursor-not-allowed"
              >
                {isAnalyzing ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Analyzing Email...
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 fill-white" />
                    Analyze Email
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleClear}
                disabled={isAnalyzing}
                className="border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium px-4 py-2.5 rounded-md text-sm flex items-center gap-2 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-500" />
                Clear
              </button>

              <button
                type="button"
                onClick={handleUseDemoEmail}
                disabled={isAnalyzing}
                className="border border-slate-200 bg-slate-50 hover:bg-slate-100 text-slate-600 font-medium px-3.5 py-2.5 rounded-md text-xs flex items-center gap-1.5 transition-colors"
              >
                <Sparkles className="w-3.5 h-3.5 text-primary" />
                Use Demo Email
              </button>
            </div>

            {/* Error simulation dropdown for testing state validation */}
            <div className="flex items-center gap-2 text-xs text-slate-400">
              <Info className="w-3.5 h-3.5" />
              <span>Simulate state:</span>
              <select
                onChange={(e) => {
                  const val = e.target.value as ErrorType;
                  if (val) triggerError(val);
                }}
                defaultValue=""
                className="bg-white border border-slate-200 rounded px-2 py-1 text-slate-600 text-xs focus:outline-none"
              >
                <option value="" disabled>Select test error state...</option>
                <option value="invalid_file">Invalid file</option>
                <option value="unsupported_file">Unsupported file</option>
                <option value="empty_input">Empty input</option>
                <option value="parsing_failure">Parsing failure</option>
                <option value="backend_failure">Backend failure</option>
              </select>
            </div>
          </div>
        </div>
      </div>

      {/* PROCESSING STATE CARD ("Analyzing email...") */}
      {(isAnalyzing || analysisComplete) && (
        <div className="bg-white border border-slate-200 rounded-lg p-6 shadow-xs space-y-6 animate-in fade-in slide-in-from-bottom-2 duration-300">
          <div className="flex items-center justify-between border-b border-slate-100 pb-4">
            <div className="flex items-center gap-3">
              {isAnalyzing ? (
                <div className="w-9 h-9 rounded-full bg-blue-50 text-primary flex items-center justify-center border border-blue-100">
                  <Loader2 className="w-5 h-5 animate-spin" />
                </div>
              ) : (
                <div className="w-9 h-9 rounded-full bg-emerald-50 text-emerald-600 flex items-center justify-center border border-emerald-100">
                  <CheckCircle2 className="w-5 h-5" />
                </div>
              )}
              <div>
                <h3 className="text-lg font-bold text-slate-800">
                  {isAnalyzing ? 'Analyzing email...' : 'Email Analysis Complete'}
                </h3>
                <p className="text-xs text-slate-500 mt-0.5">
                  {isAnalyzing
                    ? 'Processing MIME structures and querying threat intelligence pipelines'
                    : 'All forensic extraction and detection modules executed successfully'}
                </p>
              </div>
            </div>

            <span
              className={`text-xs font-semibold px-2.5 py-1 rounded-full flex items-center gap-1.5 ${
                isAnalyzing
                  ? 'bg-blue-50 text-primary border border-blue-200'
                  : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${isAnalyzing ? 'bg-primary animate-ping' : 'bg-emerald-500'}`} />
              {isAnalyzing ? 'Processing Payload' : 'Analysis Ready'}
            </span>
          </div>

          {/* Sequential Stage Execution Pipeline */}
          <div className="space-y-3">
            <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Forensic Execution Stages
            </div>

            {stages.map((stage, idx) => (
              <div
                key={stage.id}
                className={`flex items-start gap-4 p-3.5 rounded-md border transition-all ${
                  stage.status === 'completed'
                    ? 'bg-slate-50/60 border-slate-200 text-slate-800'
                    : stage.status === 'active'
                    ? 'bg-blue-50/50 border-blue-200 text-slate-900 shadow-2xs'
                    : 'bg-white border-slate-100 text-slate-400'
                }`}
              >
                <div className="mt-0.5 shrink-0">
                  {stage.status === 'completed' && (
                    <CheckCircle2 className="w-5 h-5 text-emerald-600" />
                  )}
                  {stage.status === 'active' && (
                    <Loader2 className="w-5 h-5 text-primary animate-spin" />
                  )}
                  {stage.status === 'pending' && (
                    <div className="w-5 h-5 rounded-full border-2 border-slate-300 flex items-center justify-center text-[10px] font-bold text-slate-400">
                      {idx + 1}
                    </div>
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <h4 className={`text-sm font-semibold ${stage.status === 'pending' ? 'text-slate-400' : 'text-slate-800'}`}>
                      {stage.name}
                    </h4>
                    <span className="text-[11px] font-medium text-slate-400">
                      {stage.status === 'completed' && 'Done'}
                      {stage.status === 'active' && 'Running...'}
                      {stage.status === 'pending' && 'Queued'}
                    </span>
                  </div>
                  <p className={`text-xs mt-0.5 ${stage.status === 'pending' ? 'text-slate-400' : 'text-slate-500'}`}>
                    {stage.detail}
                  </p>
                </div>
              </div>
            ))}
          </div>

          {/* Post-Completion Summary / Call to Action */}
          {analysisComplete && (
            <div className="pt-4 border-t border-slate-100 flex items-center justify-between flex-wrap gap-4 bg-slate-50 p-4 rounded-md border border-slate-200">
              <div>
                <h4 className="text-sm font-semibold text-slate-800 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-primary" />
                  Payload Ingested to Docket Pipeline
                </h4>
                <p className="text-xs text-slate-500 mt-0.5">
                  Email structure parsed into SOC threat database. Triage docket generated.
                </p>
              </div>

              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleClear}
                  className="border border-slate-200 bg-white hover:bg-slate-50 text-slate-700 font-medium px-4 py-2 rounded-md text-xs transition-colors"
                >
                  Analyze Another Email
                </button>
                <button
                  type="button"
                  onClick={() => navigate('/investigations')}
                  className="bg-primary hover:bg-primary-hover text-white font-semibold px-4 py-2 rounded-md text-xs flex items-center gap-1.5 transition-colors shadow-2xs"
                >
                  View Investigations
                  <ChevronRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
