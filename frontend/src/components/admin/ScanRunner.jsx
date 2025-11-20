/**
 * Scan Runner Component - Start and manage scans
 */
import { useState } from 'react';
import Button from '../common/Button';
import Input from '../common/Input';
import LoadingSpinner from '../common/LoadingSpinner';
import { PlayIcon, BeakerIcon, ShieldCheckIcon } from '@heroicons/react/24/outline';

const ScanRunner = ({ engagement, onScanComplete }) => {
  const [target, setTarget] = useState('');
  const [scanType, setScanType] = useState('full');
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(null);
  const [error, setError] = useState(null);

  const handleStartScan = async (e) => {
    e.preventDefault();
    if (!target.trim()) {
      setError('Please enter a target');
      return;
    }

    setIsScanning(true);
    setError(null);
    setScanProgress({ phase: 'Starting scan...', progress: 0 });

    try {
      const engagementService = (await import('../../services/engagement.service')).default;

      if (scanType === 'recon') {
        setScanProgress({ phase: 'Running reconnaissance...', progress: 50 });
        const result = await engagementService.runRecon(target, engagement.id);
        setScanProgress({ phase: 'Reconnaissance complete!', progress: 100 });
        setTimeout(() => {
          onScanComplete(result);
          resetForm();
        }, 1000);
      } else if (scanType === 'vuln') {
        setScanProgress({ phase: 'Scanning for vulnerabilities...', progress: 50 });
        const result = await engagementService.runVulnerabilityScan(target, engagement.id);
        setScanProgress({ phase: 'Vulnerability scan complete!', progress: 100 });
        setTimeout(() => {
          onScanComplete(result);
          resetForm();
        }, 1000);
      } else {
        // Full scan
        setScanProgress({ phase: 'Running reconnaissance...', progress: 25 });
        await new Promise(resolve => setTimeout(resolve, 500));

        setScanProgress({ phase: 'Scanning for vulnerabilities...', progress: 50 });
        const result = await engagementService.runFullScan(target, engagement.id);

        setScanProgress({ phase: 'Analyzing results...', progress: 75 });
        await new Promise(resolve => setTimeout(resolve, 500));

        setScanProgress({ phase: 'Full assessment complete!', progress: 100 });
        setTimeout(() => {
          onScanComplete(result);
          resetForm();
        }, 1000);
      }
    } catch (err) {
      console.error('Scan error:', err);
      setError(err.response?.data?.error || 'Scan failed');
      setScanProgress(null);
      setIsScanning(false);
    }
  };

  const resetForm = () => {
    setTarget('');
    setScanType('full');
    setIsScanning(false);
    setScanProgress(null);
    setError(null);
  };

  return (
    <div className="space-y-4">
      <form onSubmit={handleStartScan} className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Target *
          </label>
          <Input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="example.com, 192.168.1.1, https://example.com"
            disabled={isScanning}
            className={error ? 'border-red-500' : ''}
          />
          <p className="mt-1 text-xs text-gray-500">
            Enter a domain, IP address, or URL to scan
          </p>
          {error && (
            <p className="mt-1 text-sm text-red-600 dark:text-red-400">{error}</p>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
            Scan Type *
          </label>
          <select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
            disabled={isScanning}
            className="input w-full"
          >
            <option value="full">Full Assessment (Recon + Vulnerabilities)</option>
            <option value="recon">Reconnaissance Only</option>
            <option value="vuln">Vulnerability Scan Only</option>
          </select>
        </div>

        {/* Scan Progress */}
        {isScanning && scanProgress && (
          <div className="p-4 bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg">
            <div className="flex items-center gap-3 mb-2">
              <LoadingSpinner size="sm" />
              <span className="text-sm font-medium text-blue-900 dark:text-blue-100">
                {scanProgress.phase}
              </span>
            </div>
            <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
              <div
                className="bg-blue-600 h-2 rounded-full transition-all duration-500"
                style={{ width: `${scanProgress.progress}%` }}
              />
            </div>
          </div>
        )}

        <div className="flex gap-3">
          <Button
            type="submit"
            disabled={isScanning}
            className="flex-1"
          >
            <PlayIcon className="h-4 w-4 inline-block mr-2" />
            {isScanning ? 'Scanning...' : 'Start Scan'}
          </Button>
          {isScanning && (
            <Button
              type="button"
              variant="secondary"
              onClick={resetForm}
            >
              Cancel
            </Button>
          )}
        </div>
      </form>

      {/* Scan Type Info */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
        <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <div className="flex items-center gap-2 font-medium text-gray-900 dark:text-gray-100 mb-1">
            <BeakerIcon className="h-4 w-4 text-primary-600" />
            Reconnaissance
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Domain info, DNS, WHOIS, subdomains, and technology detection
          </p>
        </div>
        <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <div className="flex items-center gap-2 font-medium text-gray-900 dark:text-gray-100 mb-1">
            <ShieldCheckIcon className="h-4 w-4 text-warning-600" />
            Vulnerabilities
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Security headers, SSL/TLS, common vulnerabilities, and misconfigurations
          </p>
        </div>
        <div className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
          <div className="flex items-center gap-2 font-medium text-gray-900 dark:text-gray-100 mb-1">
            <PlayIcon className="h-4 w-4 text-success-600" />
            Full Assessment
          </div>
          <p className="text-gray-600 dark:text-gray-400">
            Complete security assessment with AI-powered analysis
          </p>
        </div>
      </div>
    </div>
  );
};

export default ScanRunner;
