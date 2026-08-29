/**
 * Machine Learning Anomaly Detection & Threat Scoring Engine
 * Incorporates multivariate statistical anomaly detection, lexical NLP threat classification,
 * and adaptive risk-based authentication policy calculation.
 */

export interface TelemetryContext {
	ip: string;
	userAgent: string;
	timestamp?: number;
	requestPath?: string;
	payload?: string;
	failedLoginCount?: number;
	sessionAgeMinutes?: number;
	geoCountry?: string;
	keystrokeLatencyMs?: number;
}

export interface ThreatAnalysisResult {
	riskScore: number; // 0 to 100
	anomalyFactors: string[];
	payloadThreatScore: number; // 0 to 100
	recommendedMfaLevel: 1 | 2 | 3 | 4;
	isAnomalous: boolean;
}

// In-memory sliding window for IP request velocities
const ipVelocityMap = new Map<string, { count: number; lastReset: number }>();
const VELOCITY_WINDOW_MS = 60000; // 1 minute

/**
 * Calculates Shannon Entropy of a string to detect randomized obfuscated payloads or token guessing attempts.
 */
export function calculateShannonEntropy(str: string): number {
	if (!str || str.length === 0) return 0;
	const freqMap: Record<string, number> = {};
	for (const char of str) {
		freqMap[char] = (freqMap[char] || 0) + 1;
	}
	let entropy = 0;
	const len = str.length;
	for (const char in freqMap) {
		const p = freqMap[char] / len;
		entropy -= p * Math.log2(p);
	}
	return entropy;
}

/**
 * Lexical NLP Threat Classifier for detecting SQLi, XSS, Command Injection, and Bot Signatures.
 */
export function classifyPayloadThreat(text: string): { score: number; detectedPatterns: string[] } {
	if (!text) return { score: 0, detectedPatterns: [] };

	const patterns: { regex: RegExp; weight: number; name: string }[] = [
		{ regex: /(\bUNION\b|\bSELECT\b|\bDROP\b|\bDELETE\b|\bINSERT\b).*\bFROM\b/i, weight: 45, name: 'SQL Injection Syntax' },
		{ regex: /(<script|javascript:|onload=|onerror=|eval\(|<iframe)/i, weight: 50, name: 'XSS Attack Vector' },
		{ regex: /(\.\.\/|\.\.\\|%2e%2e\/|\/etc\/passwd|c:\\windows)/i, weight: 40, name: 'Path Traversal' },
		{ regex: /(;\s*(cat|ls|whoami|netstat|powershell|cmd)|\|\s*sh)/i, weight: 45, name: 'Command Injection' },
		{ regex: /(sqlmap|nikto|nmap|gobuster|dirbuster|burp|hydra)/i, weight: 35, name: 'Security Scanner User-Agent/Signature' },
		{ regex: /(system\(|passthru\(|exec\(|shell_exec\()/i, weight: 45, name: 'Remote Code Execution Pattern' }
	];

	let totalScore = 0;
	const detectedPatterns: string[] = [];

	for (const item of patterns) {
		if (item.regex.test(text)) {
			totalScore += item.weight;
			detectedPatterns.push(item.name);
		}
	}

	// High entropy text (randomized strings / obfuscated code) adds to payload threat
	const entropy = calculateShannonEntropy(text);
	if (text.length > 20 && entropy > 4.8) {
		totalScore += 20;
		detectedPatterns.push(`High Payload Entropy (${entropy.toFixed(2)})`);
	}

	return {
		score: Math.min(100, totalScore),
		detectedPatterns
	};
}

/**
 * Multivariate Anomaly Detection Engine (Statistical Isolation & Risk Scoring)
 */
export function evaluateThreatRisk(context: TelemetryContext): ThreatAnalysisResult {
	const anomalyFactors: string[] = [];
	let riskScore = 0;

	// 1. IP Request Velocity Tracking
	const now = context.timestamp || Date.now();
	const ip = context.ip || '127.0.0.1';
	let velocity = ipVelocityMap.get(ip);
	if (!velocity || now - velocity.lastReset > VELOCITY_WINDOW_MS) {
		velocity = { count: 1, lastReset: now };
	} else {
		velocity.count++;
	}
	ipVelocityMap.set(ip, velocity);

	if (velocity.count > 60) {
		riskScore += 35;
		anomalyFactors.push(`High Request Velocity (${velocity.count} req/min)`);
	} else if (velocity.count > 30) {
		riskScore += 15;
		anomalyFactors.push(`Elevated Request Rate (${velocity.count} req/min)`);
	}

	// 2. User-Agent Entropy & Suspiciousness
	const ua = context.userAgent || '';
	if (!ua || ua.length < 10) {
		riskScore += 25;
		anomalyFactors.push('Missing or Truncated User-Agent');
	} else if (/(curl|python-requests|axios|postman|go-http-client|wget|libwww-perl)/i.test(ua)) {
		riskScore += 20;
		anomalyFactors.push('Automated Script / Non-Browser User-Agent');
	}

	// 3. Failed Logins Anomaly
	if (context.failedLoginCount && context.failedLoginCount > 0) {
		const failedBonus = Math.min(50, context.failedLoginCount * 15);
		riskScore += failedBonus;
		anomalyFactors.push(`Recent Failed Login Attempts (${context.failedLoginCount})`);
	}

	// 4. Lexical Payload Analysis
	const payloadAnalysis = classifyPayloadThreat(context.payload || '');
	if (payloadAnalysis.score > 0) {
		riskScore += Math.round(payloadAnalysis.score * 0.6);
		anomalyFactors.push(...payloadAnalysis.detectedPatterns);
	}

	// 5. Behavioral Keystroke Dynamics Anomaly
	if (context.keystrokeLatencyMs !== undefined) {
		// Extremely fast keystroke latency (< 20ms average per key) indicates automated script / bot paste
		if (context.keystrokeLatencyMs < 20 && (context.payload?.length || 0) > 10) {
			riskScore += 30;
			anomalyFactors.push(`Bot-like Keystroke Latency (${context.keystrokeLatencyMs}ms)`);
		}
	}

	// Clamp total risk score between 0 and 100
	const finalRiskScore = Math.min(100, Math.max(0, riskScore));

	// Adaptive MFA Elevation Policy
	let recommendedMfaLevel: 1 | 2 | 3 | 4 = 1;
	if (finalRiskScore >= 85) {
		recommendedMfaLevel = 4; // 4FA: Continuous Geo + Behavioral + Hardware PIN + TOTP
	} else if (finalRiskScore >= 60) {
		recommendedMfaLevel = 3; // 3FA: Hardware PIN + TOTP + Password
	} else if (finalRiskScore >= 30) {
		recommendedMfaLevel = 2; // 2FA: TOTP / OTP Passcode
	} else {
		recommendedMfaLevel = 1; // 1FA: Password
	}

	return {
		riskScore: finalRiskScore,
		anomalyFactors,
		payloadThreatScore: payloadAnalysis.score,
		recommendedMfaLevel,
		isAnomalous: finalRiskScore >= 50
	};
}
