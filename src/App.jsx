import React, { useState, useMemo, useCallback, useRef } from "react";
import {
  ShieldCheck,
  Scan,
  Lock,
  Code,
  Key,
  File,
  ExternalLink,
  Search,
  Hash,
  Unlock,
  Loader2,
  Image,
  Layers,
  Save,
  Edit,
  Info,
  Check,
  X,
} from "lucide-react";

function arrayBufferToBase64(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.byteLength; i++)
    binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

async function hashMessage(message, algorithm) {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest(algorithm, msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

const COLORS_FIXED = {
  indigo: {
    name: "Indigo",
    primary: "indigo-600",
    bg: "bg-indigo-600",
    hoverBg: "hover:bg-indigo-700",
    text: "text-indigo-600",
    border: "border-indigo-500",
    shadow: "shadow-indigo-500/50",
  },
};
const colors = COLORS_FIXED.indigo;

const TABS = [
  { id: "url", name: "URL Scan", icon: ExternalLink },
  { id: "malware", name: "File Scan", icon: File },
  { id: "crypto", name: "Cryptography Tools", icon: Lock },
  { id: "stego", name: "Steganography", icon: Image },
  { id: "password", name: "Password Check", icon: Key },
];

const HASH_ALGORITHMS = [
  { value: "SHA-256", name: "SHA-256 (Recommended)", supported: true },
  { value: "SHA-512", name: "SHA-512", supported: true },
  { value: "SHA-384", name: "SHA-384", supported: true },
  { value: "SHA-224", name: "SHA-224", supported: true },
  { value: "SHA-1", name: "SHA-1 (Deprecated)", supported: true },
  { value: "MD5", name: "MD5 (Unsupported by Web Crypto)", supported: false },
  { value: "MD4", name: "MD4 (Unsupported by Web Crypto)", supported: false },
  { value: "MD2", name: "MD2 (Unsupported by Web Crypto)", supported: false },
];

const UrlScanner = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const scanUrl = () => {
    if (!url) return;
    setIsLoading(true);
    setResult(null);

    setTimeout(() => {
      const isMalicious = url.includes("badsite") || url.includes("phish");
      const safetyRating = isMalicious ? "High Risk" : "Safe";
      const threatDetails = isMalicious
        ? "Detected suspicious patterns and cross-site scripting risks."
        : "No immediate threats detected.";

      setResult({
        url,
        safetyRating,
        threatDetails,
        timestamp: new Date().toLocaleTimeString(),
      });
      setIsLoading(false);
    }, 1500);
  };

  const resultColor =
    result?.safetyRating === "Safe" ? "text-emerald-500" : "text-rose-500";

  return (
    <div className="space-y-6 p-4">
      <h2 className="text-2xl font-semibold flex items-center gap-2 text-gray-800">
        <ExternalLink className={`w-5 h-5 ${colors.text}`} /> URL Security Scan
      </h2>
      <p className="text-sm text-gray-600">
        Analyze a URL against a simulated threat intelligence database for
        malicious activity.
      </p>
      <p className={`text-gray-600 border-l-4 ${colors.border} pl-3 py-1`}>
        *This is a simulated scan.
      </p>

      <div className="flex flex-col md:flex-row gap-3">
        <input
          type="url"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="Enter a URL (e.g., https://www.google.com/)"
          className="flex-grow p-3 border border-gray-300 rounded-lg focus:ring-current focus:border-current transition duration-150"
          style={{
            borderColor: colors.border.replace("border-", "#"),
            "--tw-ring-color": colors.text.replace("text-", "#"),
          }}
        />
        <button
          onClick={scanUrl}
          disabled={isLoading || !url}
          className={`px-6 py-3 text-white font-medium rounded-lg shadow-md ${colors.bg} ${colors.hoverBg} transition duration-150 disabled:opacity-50 flex items-center justify-center gap-2`}
        >
          {isLoading ? (
            <Loader2 className="w-5 h-5 animate-spin" />
          ) : (
            <Scan className="w-5 h-5" />
          )}
          {isLoading ? "Scanning..." : "Scan URL"}
        </button>
      </div>

      {result && (
        <div className="mt-6 p-4 bg-white border border-gray-200 rounded-xl shadow-lg">
          <h3 className="text-xl font-bold mb-3 text-gray-900">
            Scan Results for: <span className={colors.text}>{result.url}</span>
          </h3>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-gray-500">Overall Rating:</p>
              <p className={`font-bold text-lg ${resultColor}`}>
                {result.safetyRating}
              </p>
            </div>
            <div className="col-span-2">
              <p className="text-gray-500">Detailed Analysis:</p>
              <p className="mt-1 bg-gray-50 p-3 rounded-lg border text-gray-700">
                {result.threatDetails}
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

const MalwareScanner = () => {
  const [fileName, setFileName] = useState("");
  const [scanResult, setScanResult] = useState(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setFileName(file.name);
      setScanResult(null);
    } else {
      setFileName("");
    }
  };

  const runScan = () => {
    if (!fileName) return;
    setIsLoading(true);
    setScanResult(null);

    setTimeout(() => {
      let isMalware =
        fileName.toLowerCase().includes("virus") ||
        fileName.toLowerCase().includes(".exe");
      if (fileName.length > 20) isMalware = !isMalware;

      const status = isMalware ? "Threat Detected" : "Clean";
      const details = isMalware
        ? `Identified file hash signature matching Trojan variant X90.`
        : `File is clean based on current signatures.`;
      const color = isMalware ? "text-rose-600" : "text-emerald-600";

      setScanResult({ status, details, color });
      setIsLoading(false);
    }, 2500);
  };

  return (
    <div className="space-y-6 p-4">
      <h2 className="text-2xl font-semibold flex items-center gap-2 text-gray-800">
        <File className={`w-5 h-5 ${colors.text}`} /> Virus/Malware File Scan
      </h2>
      <p className="text-sm text-gray-600">
        Simulate scanning a local file against a malware signature database.
      </p>
      <p className={`text-gray-600 border-l-4 ${colors.border} pl-3 py-1`}>
        *File operations and threat analysis are simulated.
      </p>

      <div className="flex flex-col gap-3">
        <label className="block text-sm font-medium text-gray-700">
          Select File to Simulate Scan
        </label>
        <div className="flex items-center space-x-4">
          <input
            type="file"
            id="file-upload"
            onChange={handleFileChange}
            className="hidden"
          />
          <label
            htmlFor="file-upload"
            className="cursor-pointer bg-white py-2 px-4 border border-gray-300 rounded-lg shadow-sm text-sm font-medium text-gray-700 hover:bg-gray-50 transition duration-150"
          >
            Choose File
          </label>
          <span className="text-gray-500 truncate flex-grow">
            {fileName || "No file selected"}
          </span>
        </div>

        <button
          onClick={runScan}
          disabled={!fileName || isLoading}
          className={`w-full py-3 mt-3 bg-emerald-600 text-white font-medium rounded-lg shadow-md hover:bg-emerald-700 transition duration-150 disabled:opacity-50 flex items-center justify-center gap-2`}
        >
          {isLoading ? (
            <Loader2 className="w-5 h-5 animate-spin" />
          ) : (
            <ShieldCheck className="w-5 h-5" />
          )}
          {isLoading ? "Analyzing..." : "Run Simulated Scan"}
        </button>
      </div>

      {scanResult && (
        <div className="mt-6 p-4 bg-white border border-gray-200 rounded-xl shadow-lg">
          <h3 className="text-xl font-bold mb-3 text-gray-900">Scan Report</h3>
          <p className="text-gray-500">
            File Name:{" "}
            <span className="font-semibold text-gray-800">{fileName}</span>
          </p>
          <p className="text-gray-500 mt-2">Status:</p>
          <p className={`font-bold text-xl ${scanResult.color}`}>
            {scanResult.status}
          </p>
          <p className="text-gray-500 mt-4">Details:</p>
          <p className="mt-1 bg-gray-50 p-3 rounded-lg border break-words">
            {scanResult.details}
          </p>
        </div>
      )}
    </div>
  );
};

const Base64Converter = () => {
  const [input, setInput] = useState("");
  const [output, setOutput] = useState("");
  const [error, setError] = useState("");

  const encode = useCallback(() => {
    setError("");
    if (!input) {
      setOutput("");
      return;
    }
    try {
      setOutput(btoa(input));
    } catch {
      setError("Encoding failed.");
    }
  }, [input]);

  const decode = useCallback(() => {
    setError("");
    if (!input) {
      setOutput("");
      return;
    }
    try {
      setOutput(atob(input));
    } catch {
      setError("Decoding failed: Invalid Base64 input.");
    }
  }, [input]);

  return (
    <div className="p-4 bg-white rounded-lg shadow-inner border border-gray-100 space-y-4">
      <h3
        className={`text-xl font-semibold flex items-center gap-2 ${colors.text}`}
      >
        <Edit className="w-5 h-5" /> Base64 Encoder and Decoder
      </h3>
      <p className="text-sm text-gray-600">
        Convert plain text to Base64 (Encode) or decode a Base64 string back to
        text.
      </p>

      <div className="grid md:grid-cols-2 gap-4">
        <div className="space-y-2">
          <label
            htmlFor="base64-input"
            className="block text-sm font-medium text-gray-700"
          >
            Input Text/Base64
          </label>
          <textarea
            id="base64-input"
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setOutput("");
              setError("");
            }}
            placeholder="Enter text or Base64 string here..."
            rows="6"
            className="w-full p-2 border rounded-lg"
          ></textarea>
          <div className="flex gap-2">
            <button
              onClick={encode}
              disabled={!input}
              className={`flex-1 py-2 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 transition disabled:opacity-50 text-sm`}
            >
              Encode
            </button>
            <button
              onClick={decode}
              disabled={!input}
              className={`flex-1 py-2 bg-rose-500 text-white rounded-lg hover:bg-rose-600 transition disabled:opacity-50 text-sm`}
            >
              Decode
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <label className="block text-sm font-medium text-gray-700">
            Output Result
          </label>
          <textarea
            readOnly
            value={output}
            placeholder="Result will appear here..."
            rows="6"
            className="w-full p-2 border rounded-lg bg-gray-50 font-mono text-xs"
          ></textarea>
          {error && <p className="text-sm text-rose-500">{error}</p>}
        </div>
      </div>
    </div>
  );
};

const HashingAlgorithm = () => {
  const [input, setInput] = useState("");
  const [salt, setSalt] = useState("");
  const [algorithm, setAlgorithm] = useState("SHA-256");
  const [hash, setHash] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [decryptionStatus, setDecryptionStatus] = useState("");

  const selectedAlgorithm = useMemo(
    () => HASH_ALGORITHMS.find((a) => a.value === algorithm),
    [algorithm]
  );

  const generateHash = useCallback(async () => {
    if (!input || !selectedAlgorithm.supported) return;

    setIsLoading(true);
    setHash("");
    setDecryptionStatus("");

    const saltedMessage = input + salt;

    try {
      const result = await hashMessage(saltedMessage, algorithm);
      setHash(result);
    } catch (error) {
      setHash("Error generating hash. Check console for details.");
      console.error(error);
    } finally {
      setIsLoading(false);
    }
  }, [input, salt, algorithm, selectedAlgorithm]);

  const handleDecryptSimulation = () => {
    if (!hash) {
      setDecryptionStatus("Please generate a hash value first.");
      return;
    }
    setDecryptionStatus("");
    setIsLoading(true);

    setTimeout(() => {
      setDecryptionStatus(
        'Decryption Failed. Hashing is a one-way, irreversible function. We can only attempt to "crack" a hash using brute-force or lookup tables.'
      );
      setIsLoading(false);
    }, 1500);
  };

  return (
    <div className="p-4 bg-white rounded-lg shadow-inner border border-gray-100 space-y-4">
      <h3
        className={`text-xl font-semibold flex items-center gap-2 ${colors.text}`}
      >
        <Hash className="w-5 h-5" /> Hashing Algorithm
      </h3>
      <p className="text-sm text-gray-600">
        Generate irreversible hash values using various algorithms with optional
        salt.
      </p>

      <div className="space-y-2">
        <label
          htmlFor="hash-algo"
          className="block text-sm font-medium text-gray-700 mb-1"
        >
          Select Hash Algorithm
        </label>
        <select
          id="hash-algo"
          value={algorithm}
          onChange={(e) => {
            setAlgorithm(e.target.value);
            setHash("");
          }}
          className="w-full p-2 border border-gray-300 rounded-lg focus:ring-current focus:border-current"
          style={{
            borderColor: colors.border.replace("border-", "#"),
            "--tw-ring-color": colors.text.replace("text-", "#"),
          }}
        >
          {HASH_ALGORITHMS.map((alg) => (
            <option key={alg.value} value={alg.value} disabled={!alg.supported}>
              {alg.name}
            </option>
          ))}
        </select>
        {!selectedAlgorithm.supported && (
          <p className="text-xs text-rose-500 mt-1">
            MD2, MD4, and MD5 are not supported by the browser's native Web
            Crypto API.
          </p>
        )}
      </div>

      <div>
        <label
          htmlFor="salt"
          className="block text-sm font-medium text-gray-700 mb-1"
        >
          Salt
        </label>
        <input
          id="salt"
          type="text"
          value={salt}
          onChange={(e) => setSalt(e.target.value)}
          placeholder="Optional salt value"
          className="w-full p-2 border border-gray-300 rounded-lg font-mono text-sm"
        />
      </div>

      <textarea
        value={input}
        onChange={(e) => setInput(e.target.value)}
        placeholder="Enter message to hash..."
        rows="3"
        className="w-full p-2 border border-gray-300 rounded-lg focus:ring-current focus:border-current"
        style={{
          borderColor: colors.border.replace("border-", "#"),
          "--tw-ring-color": colors.text.replace("text-", "#"),
        }}
      ></textarea>

      <div className="flex gap-2">
        <button
          onClick={handleDecryptSimulation}
          disabled={isLoading || !hash}
          className={`flex-1 py-2 bg-rose-500 text-white font-medium rounded-lg hover:bg-rose-600 transition disabled:opacity-50 flex items-center justify-center gap-2`}
        >
          {isLoading && decryptionStatus ? (
            <Loader2 className="w-5 h-5 animate-spin" />
          ) : (
            <Unlock className="w-5 h-5" />
          )}
          Decrypt Hash Value
        </button>
        <button
          onClick={generateHash}
          disabled={isLoading || !input || !selectedAlgorithm.supported}
          className={`flex-1 py-2 ${colors.bg} text-white font-medium rounded-lg ${colors.hoverBg} transition disabled:opacity-50 flex items-center justify-center gap-2`}
        >
          {isLoading && !decryptionStatus ? (
            <Loader2 className="w-5 h-5 animate-spin" />
          ) : (
            "Generate Hash Value"
          )}
        </button>
      </div>

      <div className="break-all mt-3 p-3 bg-gray-50 border rounded-lg text-sm">
        <p className="font-medium text-gray-600">Resulting Hash Value:</p>
        <textarea
          readOnly
          value={hash}
          placeholder="Generated hash will appear here..."
          rows="2"
          className="w-full p-1 border-none bg-transparent font-mono text-gray-800 break-all resize-none focus:ring-0"
        ></textarea>
      </div>

      {decryptionStatus && (
        <div className="p-3 bg-rose-100 border border-rose-400 text-rose-700 rounded-lg text-sm">
          <p className="font-semibold">Cracking Simulation Result:</p>
          <p>{decryptionStatus}</p>
        </div>
      )}
    </div>
  );
};

const HashIdentifierTool = () => {
  const [inputHash, setInputHash] = useState("");
  const [detectedType, setDetectedType] = useState("Unknown");

  const detectHash = useCallback((hashValue) => {
    const len = hashValue.length;
    const isHex = /^[0-9a-fA-F]+$/.test(hashValue);

    if (!hashValue) return "Unknown";
    if (!isHex) return "Not a valid hexadecimal hash";

    switch (len) {
      case 32:
        return "MD5 (128-bit) or NTLM";
      case 40:
        return "SHA-1 (160-bit)";
      case 56:
        return "SHA-224";
      case 64:
        return "SHA-256 (256-bit)";
      case 96:
        return "SHA-384";
      case 128:
        return "SHA-512 (512-bit)";
      default:
        return `Unknown (Length: ${len} characters)`;
    }
  }, []);

  const handleInputChange = (e) => {
    const value = e.target.value.trim();
    setInputHash(value);
    setDetectedType(detectHash(value));
  };

  return (
    <div className="p-4 bg-white rounded-lg shadow-inner border border-gray-100 space-y-4">
      <h3
        className={`text-xl font-semibold flex items-center gap-2 ${colors.text}`}
      >
        <Search className="w-5 h-5" /> Hash Identifier Tool
      </h3>
      <p className="text-sm text-gray-600">
        Paste any hash value here to detect the likely algorithm based on its
        length and format.
      </p>

      <input
        type="text"
        value={inputHash}
        onChange={handleInputChange}
        placeholder="Paste hash value to identify (e.g., 9F86D081884C7D659A2FEAA0C55AD015A3C544F1)"
        className="w-full p-3 border border-gray-300 rounded-lg font-mono text-sm"
      />

      <div className={`mt-3 p-3 bg-gray-50 border rounded-lg ${colors.border}`}>
        <p className="font-medium text-gray-600">Detected Algorithm:</p>
        <p className={`font-bold text-xl ${colors.text} break-all`}>
          {detectedType}
        </p>
      </div>
    </div>
  );
};

const PasswordStrengthChecker = () => {
  const [password, setPassword] = useState("");

  const generateRandomPassword = (length = 16) => {
    const charset =
      "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
    let newPassword = "";
    const charArray = charset.split("");

    for (let i = 0; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charArray.length);
      newPassword += charArray[randomIndex];
    }
    return newPassword;
  };

  const scoreAndReport = useMemo(() => {
    const checks = {
      length: password.length >= 8,
      upper: /[A-Z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[!@#$%^&*()_+~`|}{[\]:;?><,./-=]/.test(password),
    };

    let score = 0;
    if (checks.length) score += 1;
    if (checks.upper) score += 1;
    if (checks.number) score += 1;
    if (checks.special) score += 1;

    let strength = "Weak";
    let colorClass = "text-rose-500";

    if (score === 4) {
      strength = "Moderate";
      colorClass = "text-yellow-500";
    } else if (score >= 5 && password.length >= 12) {
      strength = "Strong";
      colorClass = "text-emerald-500";
    } else if (score >= 5) {
      strength = "Good";
      colorClass = "text-blue-500";
    }

    return { score, strength, colorClass, checks };
  }, [password]);

  const handleSuggestPassword = () => {
    const newPassword = generateRandomPassword();
    setPassword(newPassword);
  };

  const getBarColor = () => {
    if (scoreAndReport.strength === "Weak") return "bg-rose-500";
    if (scoreAndReport.strength === "Moderate") return "bg-yellow-500";
    if (scoreAndReport.strength === "Good") return "bg-blue-500";
    if (scoreAndReport.strength === "Strong") return "bg-emerald-500";
    return "bg-gray-300";
  };

  const getBarWidth = () => {
    if (password.length === 0) return "w-0";
    const scoreMap = { Weak: 1, Moderate: 2, Good: 3, Strong: 4 };
    const widthPercent = (scoreMap[scoreAndReport.strength] / 4) * 100;
    return `w-[${Math.min(widthPercent, 100)}%]`;
  };

  const ChecklistItem = ({ label, passed }) => (
    <li className="flex items-center space-x-2 text-sm text-gray-700">
      {passed ? (
        <Check className="w-4 h-4 text-emerald-500 flex-shrink-0" />
      ) : (
        <X className="w-4 h-4 text-rose-500 flex-shrink-0" />
      )}
      <span>{label}</span>
    </li>
  );

  return (
    <div className="space-y-6 p-4">
      <h2 className="text-2xl font-semibold flex items-center gap-2 text-gray-800">
        <Key className={`w-5 h-5 ${colors.text}`} /> Password Strength Check
      </h2>
      <p className="text-sm text-gray-600">
        Analyze password complexity and receive recommendations to enhance
        security.
      </p>

      <div className="space-y-2">
        <label
          htmlFor="password-input"
          className="block text-sm font-medium text-gray-700"
        >
          Enter Password
        </label>
        <input
          id="password-input"
          type="text"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Type your password here..."
          className="w-full p-3 border border-gray-300 rounded-lg font-mono text-base"
        />
      </div>

      {password.length > 0 && (
        <div className="space-y-4">
          <div className="space-y-1">
            <p className="text-sm font-medium text-gray-700">Strength:</p>
            <div className="h-2 bg-gray-200 rounded-full overflow-hidden">
              <div
                className={`h-full transition-all duration-500 ${getBarColor()} ${getBarWidth()}`}
                style={{
                  width: getBarWidth().replace("w-[", "").replace("%]", "%"),
                }}
              ></div>
            </div>
            <p className={`text-lg font-bold ${scoreAndReport.colorClass}`}>
              {scoreAndReport.strength}
            </p>
          </div>

          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200 space-y-2">
            <p className="font-semibold text-gray-800">
              Security Report Checklist
            </p>
            <ul className="grid sm:grid-cols-2 gap-2">
              <ChecklistItem
                label="8+ Characters Long"
                passed={scoreAndReport.checks.length}
              />
              <ChecklistItem
                label="Contains Uppercase Letters"
                passed={scoreAndReport.checks.upper}
              />
              <ChecklistItem
                label="Contains Numbers (0-9)"
                passed={scoreAndReport.checks.number}
              />
              <ChecklistItem
                label="Contains Special Characters"
                passed={scoreAndReport.checks.special}
              />
            </ul>
          </div>

          {scoreAndReport.strength === "Weak" && (
            <div className="p-3 bg-rose-100 border border-rose-400 text-rose-700 rounded-lg text-sm flex justify-between items-center">
              <p className="font-semibold">
                Your password is Weak. Try adding special characters, numbers,
                and increase the length.
              </p>
              <button
                onClick={handleSuggestPassword}
                className="ml-4 px-3 py-1 bg-rose-600 text-white rounded-md hover:bg-rose-700 transition flex-shrink-0"
              >
                Suggest New
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const Steganography = () => {
  const [secretMessage, setSecretMessage] = useState("");
  const [carrierImageFile, setCarrierImageFile] = useState(null);
  const [stegoImage, setStegoImage] = useState(null);
  const [fileToExtract, setFileToExtract] = useState(null);
  const [extractedMessage, setExtractedMessage] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const canvasRef = useRef(null);

  const getSeed = (text) => {
    let hash = 0;
    if (text.length === 0) return 0;
    for (let i = 0; i < text.length; i++) {
      const char = text.charCodeAt(i);
      hash = (hash << 5) - hash + char;
      hash |= 0;
    }
    return Math.abs(hash);
  };
  const textToBinary = (text) => {
    let binary = "";
    for (let i = 0; i < text.length; i++) {
      binary += text.charCodeAt(i).toString(2).padStart(8, "0");
    }
    return binary + "1111111111111110";
  };
  const binaryToText = (binary) => {
    let text = "";
    const eof = "1111111111111110";
    const eofIndex = binary.indexOf(eof);
    const messageBinary =
      eofIndex !== -1 ? binary.substring(0, eofIndex) : binary;

    for (let i = 0; i < messageBinary.length; i += 8) {
      const charCode = parseInt(messageBinary.substring(i, i + 8), 2);
      if (charCode === 0) continue;
      text += String.fromCharCode(charCode);
    }
    return text;
  };

  const resetState = () => {
    setStegoImage(null);
    setExtractedMessage("");
    setError("");
  };

  const handleCarrierImageUpload = (e) => {
    const file = e.target.files[0];
    if (file && file.type.startsWith("image/")) {
      setCarrierImageFile(file);
      resetState();
    } else {
      setCarrierImageFile(null);
      setError("Please select a valid image file (PNG/JPEG).");
    }
  };

  const handleExtractImageUpload = (e) => {
    const file = e.target.files[0];
    if (file && file.type.startsWith("image/")) {
      setFileToExtract(file);
      setExtractedMessage("");
      setError("");
    } else {
      setFileToExtract(null);
      setError("Please select a valid image file for extraction.");
    }
  };

  const embedMessage = useCallback(() => {
    if (!carrierImageFile || !secretMessage) {
      setError("Please upload an image and enter a secret message.");
      return;
    }
    setIsLoading(true);
    setError("");

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new window.Image();
      img.onload = () => {
        try {
          const canvas = canvasRef.current;
          canvas.width = img.width;
          canvas.height = img.height;
          const ctx = canvas.getContext("2d");
          ctx.drawImage(img, 0, 0);

          const imageData = ctx.getImageData(0, 0, img.width, img.height);
          const data = imageData.data;
          const binaryMessage = textToBinary(secretMessage);

          if (binaryMessage.length > data.length * 0.125) {
            setError(
              `Message too large. Max capacity is approx ${Math.floor(
                data.length / 8
              )} characters.`
            );
            setIsLoading(false);
            return;
          }

          let msgIndex = 0;
          let pixelIndex = 0;
          const skipInterval = password ? (getSeed(password) % 3) + 1 : 1;

          while (msgIndex < binaryMessage.length) {
            if (pixelIndex % skipInterval === 0) {
              const bit = parseInt(binaryMessage[msgIndex], 10);
              data[pixelIndex] = (data[pixelIndex] & 0xfe) | bit;
              msgIndex++;
            }
            pixelIndex += 4;

            if (pixelIndex >= data.length) {
              break;
            }
          }

          ctx.putImageData(imageData, 0, 0);
          setStegoImage(canvas.toDataURL("image/png"));
          setIsLoading(false);
        } catch (err) {
          setError("Error during image processing.");
          setIsLoading(false);
        }
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(carrierImageFile);
  }, [carrierImageFile, secretMessage, password]);

  const extractMessage = useCallback(() => {
    if (!fileToExtract) {
      setError("Please upload an image for extraction.");
      return;
    }
    setIsLoading(true);
    setError("");
    setExtractedMessage("");

    const reader = new FileReader();
    reader.onload = (e) => {
      const img = new window.Image();
      img.onload = () => {
        try {
          const canvas = canvasRef.current;
          canvas.width = img.width;
          canvas.height = img.height;
          const ctx = canvas.getContext("2d");
          ctx.drawImage(img, 0, 0);

          const imageData = ctx.getImageData(0, 0, img.width, img.height);
          const data = imageData.data;
          let binaryString = "";
          let pixelIndex = 0;
          const skipInterval = password ? (getSeed(password) % 3) + 1 : 1;

          while (binaryString.length < 10000 && pixelIndex < data.length) {
            if (pixelIndex % skipInterval === 0) {
              binaryString += (data[pixelIndex] & 1).toString();
            }
            if (binaryString.endsWith("1111111111111110")) break;
            pixelIndex += 4;
          }

          const message = binaryToText(binaryString);
          setExtractedMessage(
            message || "No secret message found or incorrect key."
          );
          setIsLoading(false);
        } catch (err) {
          setError("Error during image processing.");
          setIsLoading(false);
        }
      };
      img.src = e.target.result;
    };
    reader.readAsDataURL(fileToExtract);
  }, [fileToExtract, password]);

  const handleDownload = () => {
    if (stegoImage) {
      const link = document.createElement("a");
      link.href = stegoImage;
      link.download = "stego-image.png";
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
    }
  };

  return (
    <div className="space-y-6 p-4">
      <h2 className="text-2xl font-semibold flex items-center gap-2 text-gray-800">
        <Image className={`w-5 h-5 ${colors.text}`} /> Steganography (LSB Image
        Hiding)
      </h2>
      <p className="text-sm text-gray-600">
        Embed a hidden message within an image file or extract a secret using a
        key.
      </p>
      <p className={`text-gray-600 border-l-4 ${colors.border} pl-3 py-1`}>
        *Note: This utilizes Least Significant Bit (LSB) encoding on the image's
        red channel.
      </p>

      <canvas ref={canvasRef} className="hidden"></canvas>

      {error && (
        <div className="p-3 bg-rose-100 border border-rose-400 text-rose-700 rounded-lg text-sm">
          Error: {error}
        </div>
      )}

      <div className="grid md:grid-cols-2 gap-6">
        <div className="space-y-4 p-4 border rounded-xl bg-white shadow-lg border-gray-100">
          <h3
            className={`text-xl font-semibold ${colors.text} flex items-center gap-2`}
          >
            <Layers className="w-5 h-5" /> Embed Secret (Hide)
          </h3>

          <label className="block text-sm font-medium text-gray-700">
            1. Upload Carrier Image (PNG Recommended)
          </label>
          <input
            type="file"
            accept="image/*"
            onChange={handleCarrierImageUpload}
            className="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-100 file:text-gray-700 hover:file:bg-gray-200"
          />
          {carrierImageFile && (
            <p className="text-xs text-gray-500">
              Selected: {carrierImageFile.name}
            </p>
          )}

          <label className="block text-sm font-medium text-gray-700 pt-2">
            2. Secret Message
          </label>
          <textarea
            value={secretMessage}
            onChange={(e) => setSecretMessage(e.target.value)}
            placeholder="Enter the secret text to hide..."
            rows="3"
            className="w-full p-2 border rounded-lg"
          ></textarea>

          <label className="block text-sm font-medium text-gray-700 pt-2">
            3. Stego Key (Password) - Optional
          </label>
          <input
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Key for LSB pattern randomization (Use for decryption)"
            className="w-full p-2 border rounded-lg"
          />

          <button
            onClick={embedMessage}
            disabled={isLoading || !carrierImageFile || !secretMessage}
            className={`w-full py-2 bg-purple-500 text-white rounded-lg hover:bg-purple-600 transition disabled:opacity-50 flex items-center justify-center gap-2`}
          >
            {isLoading ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              "Embed Message"
            )}
          </button>

          {stegoImage && (
            <div className="mt-3 p-3 bg-gray-50 border rounded-lg flex flex-col items-center">
              <p className="font-medium text-gray-600 mb-2">
                Generated Stego-Image Preview:
              </p>
              <img
                src={stegoImage}
                alt="Stego Image"
                className="max-w-full h-auto rounded-lg shadow-md border mb-3"
              />
              <button
                onClick={handleDownload}
                className="py-2 px-4 bg-emerald-500 text-white rounded-lg hover:bg-emerald-600 transition flex items-center gap-1 text-sm"
              >
                <Save className="w-4 h-4" /> Download Stego-Image
              </button>
            </div>
          )}
        </div>

        <div className="space-y-4 p-4 border rounded-xl bg-white shadow-lg border-gray-100">
          <h3
            className={`text-xl font-semibold ${colors.text} flex items-center gap-2`}
          >
            <Unlock className="w-5 h-5" /> Extract Secret (Decrypt)
          </h3>

          <label className="block text-sm font-medium text-gray-700">
            1. Upload Stego-Image for Extraction
          </label>
          <input
            type="file"
            accept="image/*"
            onChange={handleExtractImageUpload}
            className="w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-gray-100 file:text-gray-700 hover:file:bg-gray-200"
          />
          {fileToExtract && (
            <p className="text-xs text-gray-500">
              Selected: {fileToExtract.name}
            </p>
          )}

          <label className="block text-sm font-medium text-gray-700 pt-2">
            2. Stego Key (Password)
          </label>
          <input
            type="text"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter Stego Key (Must match embedding key)"
            className="w-full p-2 border rounded-lg"
          />

          <button
            onClick={extractMessage}
            disabled={isLoading || !fileToExtract}
            className={`w-full py-2 bg-rose-500 text-white rounded-lg hover:bg-rose-600 transition disabled:opacity-50 flex items-center justify-center gap-2`}
          >
            {isLoading ? (
              <Loader2 className="w-5 h-5 animate-spin" />
            ) : (
              "Extract Message"
            )}
          </button>

          <label className="block text-sm font-medium text-gray-700 pt-2">
            Extracted Secret
          </label>
          <textarea
            readOnly
            value={extractedMessage}
            placeholder="Decrypted secret message will appear here..."
            rows="3"
            className="w-full p-2 border rounded-lg bg-gray-50 text-sm"
          ></textarea>
        </div>
      </div>
    </div>
  );
};

const CryptographySection = () => (
  <div className="space-y-6 p-4">
    <h2 className="text-2xl font-semibold flex items-center gap-2 text-gray-800">
      <Code className={`w-5 h-5 ${colors.text}`} /> Cryptography Toolkit
    </h2>
    <div className="space-y-6">
      <HashingAlgorithm />
      <HashIdentifierTool />
      <Base64Converter />
    </div>
  </div>
);

const Navbar = ({ activeTab, setActiveTab }) => {
  return (
    <nav className="bg-white shadow-md sticky top-0 z-40 border-b border-gray-100">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex justify-between items-center h-16">
          <div
            className="flex-shrink-0 flex items-center cursor-pointer"
            onClick={() => setActiveTab("home")}
          >
            <ShieldCheck className={`w-6 h-6 mr-3 ${colors.text}`} />
            <span className="text-xl font-bold text-gray-900">CyberGuard</span>
          </div>

          <div className="flex items-center space-x-4">
            <button
              onClick={() => setActiveTab("about")}
              className={`
                inline-flex items-center px-3 py-2 text-sm font-medium rounded-md transition duration-150
                ${
                  activeTab === "about"
                    ? `${colors.bg} text-white shadow-md ${colors.shadow}`
                    : "text-gray-600 hover:bg-gray-100"
                }
              `}
            >
              <Info className="w-4 h-4 mr-1.5" />
              About
            </button>
          </div>
        </div>
      </div>
    </nav>
  );
};

const AboutSection = () => (
  <div className="space-y-8 p-6 bg-white shadow-xl rounded-xl">
    <h2 className="text-3xl font-bold flex items-center gap-3 text-gray-800 border-b pb-3 border-gray-200">
      <Info className={`w-6 h-6 ${colors.text}`} /> About CyberGuard Toolkit
    </h2>

    <div className="space-y-4 text-gray-700">
      <p>
        CyberGuard is a demonstrative web application designed to explore
        fundamental concepts in cybersecurity and cryptography.
      </p>
      <p className="font-semibold text-lg text-gray-800 pt-2">
        Project Functionality:
      </p>
      <ul className="list-disc list-inside space-y-2 pl-4">
        <li>
          URL & File Scanning: Simulated real-time checks to demonstrate threat
          detection principles.
        </li>
        <li>
          Cryptography Toolkit: Provides actual hashing (SHA family) and data
          encoding/decoding utilities.
        </li>
        <li>
          Steganography: Implements LSB (Least Significant Bit) technique to
          hide text messages within image files.
        </li>
        <li>
          Password Strength: Analyzes password complexity and suggests
          improvements.
        </li>
      </ul>

      <p className="font-semibold text-lg text-gray-800 pt-2">
        Technologies Used:
      </p>
      <ul className="list-disc list-inside space-y-2 pl-4">
        <li>React (functional components and Hooks).</li>
        <li>Tailwind CSS for a modern, responsive UI.</li>
        <li>Browser's native crypto.subtle (Web Crypto API).</li>
      </ul>
    </div>
  </div>
);

const ToolSelector = ({ setActiveTab }) => (
  <div className="p-8 space-y-8">
    <h2 className="text-3xl font-extrabold text-gray-900">
      Welcome to the <span className={colors.text}>CyberGuard</span> Toolkit
    </h2>
    <p className="text-lg text-gray-600">
      Select a security tool below to begin your analysis or cryptographic
      operation.
    </p>

    <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
      {TABS.map((tab) => (
        <button
          key={tab.id}
          onClick={() => setActiveTab(tab.id)}
          className="group flex flex-col items-center justify-center p-6 bg-white rounded-xl shadow-lg hover:shadow-xl transition duration-300 transform hover:scale-[1.02] border border-gray-100 space-y-3"
        >
          <tab.icon
            className={`w-10 h-10 ${colors.text} transition-colors duration-300 group-hover:text-opacity-80`}
          />
          <h3 className="text-xl font-semibold text-gray-800">{tab.name}</h3>
          <p className="text-sm text-gray-500 text-center">
            {tab.id === "url" && "Simulate scanning a URL for threats."}
            {tab.id === "malware" && "Simulate file-based malware detection."}
            {tab.id === "crypto" && "Generate hashes and encode/decode data."}
            {tab.id === "stego" && "Hide and extract secrets inside images."}
            {tab.id === "password" &&
              "Check the strength and quality of a password."}
          </p>
        </button>
      ))}
    </div>
  </div>
);

export default function App() {
  const [activeTab, setActiveTab] = useState("home");

  const ComponentMap = useMemo(
    () => ({
      home: ToolSelector,
      about: AboutSection,
      url: UrlScanner,
      malware: MalwareScanner,
      crypto: CryptographySection,
      stego: Steganography,
      password: PasswordStrengthChecker,
    }),
    []
  );

  const ActiveComponent = ComponentMap[activeTab];

  return (
    <div
      className={`min-h-screen font-sans bg-gray-50 transition-colors duration-300`}
    >
      <script src="https://cdn.tailwindcss.com"></script>
      <style>
        {`
          @import url('https://fonts.googleapis.com/css2?family=Inter:wght@100..900&display=swap');
          body {
            font-family: 'Inter', sans-serif;
          }
        `}
      </style>

      <Navbar activeTab={activeTab} setActiveTab={setActiveTab} />

      <div className="max-w-7xl mx-auto py-10 px-4 sm:px-6 lg:px-8">
        <div className="bg-white shadow-xl rounded-xl">
          <ActiveComponent setActiveTab={setActiveTab} />
        </div>
      </div>

      <footer className="mt-10 pb-4 text-center text-gray-500 text-sm"></footer>
    </div>
  );
}
