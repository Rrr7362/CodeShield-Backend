// geminiService.js
// Responsible for ALL communication with the Gemini API.
// Constructs the prompt, sends the request, parses and
// validates the response.

import { GoogleGenerativeAI } from '@google/generative-ai';
import { config } from '../config/index.js';
import { AppError } from '../utils/AppError.js';

// ─────────────────────────────────────────────
// CLIENT INITIALIZATION
// ─────────────────────────────────────────────

const genAI = new GoogleGenerativeAI(config.geminiApiKey);

// Model selection:
// gemini-1.5-flash — fast, cost-effective, 1M context window
// gemini-1.5-pro   — more capable, higher cost
// For v1: Flash is the right tradeoff (speed + cost)
const MODEL_NAME = 'gemini-2.5-flash';

// ─────────────────────────────────────────────
// SYSTEM PROMPT
// The contract we give Gemini for every request.
// ─────────────────────────────────────────────
const SYSTEM_PROMPT = `
You are an expert application security engineer specializing in OWASP Top 10 vulnerability detection.

Your task is to analyze the provided source code files and identify security vulnerabilities.

CRITICAL OUTPUT CONSTRAINTS — THESE ARE HARD LIMITS, NOT SUGGESTIONS:

1. Report a MAXIMUM of 10 vulnerabilities total. If more than 10 exist,
   report ONLY the 10 most severe (prioritize critical, then high, then medium, then low).

2. Each field has a STRICT character limit. Truncate if needed:
   - "title": maximum 80 characters
   - "shortDescription": maximum 80 characters, ONE sentence only
   - "vulnerableCode": maximum 120 characters — a SNIPPET, not the full code block

3. Do NOT include any of these fields under any circumstances:
   - impact
   - remediation
   - remediationCode
   - references
   - detailed explanation
   These will be generated in a separate, later request. Including them
   wastes output space and will cause this response to fail.

4. Do NOT repeat the vulnerable code in full. A short identifying
   snippet (one line, truncated) is sufficient.

5. Do NOT add markdown formatting, headers, or commentary outside the JSON object.

OWASP TOP 10 2021 CATEGORIES:
A01 Broken Access Control, A02 Cryptographic Failures, A03 Injection,
A04 Insecure Design, A05 Security Misconfiguration, A06 Vulnerable Components,
A07 Authentication Failures, A08 Software Integrity Failures,
A09 Logging Failures, A10 SSRF

SEVERITY LEVELS: critical, high, medium, low

OUTPUT FORMAT — return ONLY this JSON structure, nothing else:
{
  "summary": {
    "critical": <number>,
    "high": <number>,
    "medium": <number>,
    "low": <number>,
  },
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "title": "<max 80 chars>",
      "severity": "<critical|high|medium|low>",
      "category": "<A01:2021 etc>",
      "categoryName": "<OWASP name>",
      "file": "<file path>",
      "lineNumber": <number or null>,
      "shortDescription": "<max 80 chars, one sentence>",
      "vulnerableCode": "<max 120 chars snippet>"
    }
  ]
}

Set "truncated": true in summary if you found more than 20 vulnerabilities
and had to omit lower-severity ones to stay within the limit.

Return ONLY valid JSON. No markdown code fences. No explanation text.
`.trim();
// ─────────────────────────────────────────────
// USER MESSAGE BUILDER
// Formats the file array into a structured prompt
// that gives Gemini clear file boundaries and context
// ─────────────────────────────────────────────

/**
 * Builds the user message from the files array.
 * Each file is clearly labeled with path and language.
 *
 * @param {Array<{ path: string, extension: string, content: string }>} files
 * @param {{ fullName: string, language: string }} metadata
 * @returns {string}
 */
function buildUserMessage(files, metadata) {
  const fileSection = files
    .map(file => {
      const language = getLanguageName(file.extension);
      return (
        `=== FILE: ${file.path} (${language}) ===\n` +
        `${file.content}\n` +
        `=== END FILE: ${file.path} ===`
      );
    })
    .join('\n\n');

  return `
Repository: ${metadata.fullName}
Primary Language: ${metadata.language || 'Unknown'}
Files to analyze: ${files.length}

${fileSection}

Analyze all files above for security vulnerabilities following your instructions.
Return ONLY the JSON object.
`.trim();
}

// ─────────────────────────────────────────────
// RESPONSE PARSER & VALIDATOR
// Defense layer between raw LLM output and our pipeline
// ─────────────────────────────────────────────

/**
 * Parses and validates the raw Gemini response text.
 * Applies multiple defense layers to handle non-deterministic output.
 *
 * @param {string} rawText
 * @returns {object} — validated report object
 */
function parseGeminiResponse(rawText) {

  // Defense 1: Strip markdown code fences
  // Gemini sometimes returns ```json ... ``` even when told not to
  let cleaned = rawText.trim();

  // Remove opening fence (```json or ```)
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '');
  // Remove closing fence
  cleaned = cleaned.replace(/\s*```\s*$/, '');

  cleaned = cleaned.trim();

  const firstBrace = cleaned.indexOf('{');
  const lastBrace = cleaned.lastIndexOf('}');

    if (firstBrace !== -1 && lastBrace !== -1) {
      cleaned = cleaned.slice(
        firstBrace,
        lastBrace + 1
      );
    }

  // Defense 2: Parse JSON
  let parsed;
  try {
    console.log(cleaned.slice(-1000));
    if (
    !cleaned.trim().endsWith('}')
    ) {
    throw new AppError(
    'Gemini response appears truncated.',
    500,
    'GEMINI_TRUNCATED_RESPONSE'
     );
   }
    parsed = JSON.parse(cleaned);
  } catch (parseError) {
    
        try {
        const repaired = jsonrepair(cleaned);
        parsed = JSON.parse(repaired);

        parsed.vulnerabilities =
        (parsed.vulnerabilities || []).slice(0, 20);

        console.warn(
          "[gemini] JSON repaired automatically"
        );

        if (parsed.summary?.truncated) {
         console.warn(`[gemini] Response truncated — repository had more than 20 ` +`vulnerabilities. Showing top 20 by severity.`
        );
       }

      } catch {
      throw new AppError(
      'AI analysis returned an unparseable response. Please try again.',
      500,
      'GEMINI_PARSE_ERROR'
       );

      }
    console.error('[gemini] Failed to parse response as JSON');
    // console.error('[gemini] Raw response:', rawText.slice(0, 500));
    console.error('\n===== RAW GEMINI RESPONSE =====');
    console.error(rawText);
    console.error('==============================\n');

    console.error('\n===== CLEANED RESPONSE =====');
    console.error(cleaned);
    console.error('============================\n');

    console.error(parseError);

    console.error(parseError);

const match = parseError.message.match(/position (\d+)/);

if (match) {
  const pos = Number(match[1]);

  console.error('\n===== ERROR CONTEXT =====');

  console.error(
    cleaned.substring(
      Math.max(0, pos - 300),
      pos + 300
    )
  );

  console.error('\n=========================');
}

    throw new AppError(
      'AI analysis returned an unparseable response. Please try again.',
      500,
      'GEMINI_PARSE_ERROR'
    );
  }

  // Defense 3: Structural validation
  // Ensure required top-level fields exist
  if (!parsed.summary || !Array.isArray(parsed.vulnerabilities)) {
    throw new AppError(
      'AI analysis returned an unexpected response structure.',
      500,
      'GEMINI_INVALID_STRUCTURE'
    );
  }

  // Defense 4: Normalize and fill defaults
  // Protect against missing optional fields in each vulnerability
  const normalizedVulnerabilities = parsed.vulnerabilities.map((vuln, index) => ({
    id:              vuln.id || `VULN-${String(index + 1).padStart(3, '0')}`,
    title:           sanitizeString(vuln.title || 'Untitled Vulnerability', 200),
    severity:        validateSeverity(vuln.severity),
    category:        vuln.category || 'Unknown',
    categoryName:    vuln.categoryName || 'Unknown',
    file:            sanitizeString(vuln.file || 'Unknown file', 500),
    lineNumber:      typeof vuln.lineNumber === 'number' ? vuln.lineNumber : null,
    vulnerableCode:  sanitizeString(vuln.vulnerableCode || '', 1000),
    description:     sanitizeString(vuln.shortDescription || '', 2000),
    impact:          sanitizeString(vuln.impact || '', 1000),
    // remediation:     sanitizeString(vuln.remediation || '', 2000),
    // references:      Array.isArray(vuln.references) ? vuln.references : [],
  }));

  // Defense 5: Recalculate summary from actual vulnerabilities
  // Don't trust the model's math — recalculate it ourselves
  const summary = {
    critical: normalizedVulnerabilities.filter(v => v.severity === 'critical').length,
    high:     normalizedVulnerabilities.filter(v => v.severity === 'high').length,
    medium:   normalizedVulnerabilities.filter(v => v.severity === 'medium').length,
    low:      normalizedVulnerabilities.filter(v => v.severity === 'low').length,
    totalIssues: normalizedVulnerabilities.length,
  };

  return {
    summary,
    vulnerabilities: normalizedVulnerabilities,
    positives: Array.isArray(parsed.positives)
      ? parsed.positives.map(p => sanitizeString(p, 300))
      : [],
    disclaimer: parsed.disclaimer ||
      'This analysis is AI-generated and should be verified by a qualified security engineer.',
  };
}

// ─────────────────────────────────────────────
// VALIDATION HELPERS
// ─────────────────────────────────────────────

/**
 * Validates severity value against allowed values.
 * Defaults to 'medium' if invalid — conservative default.
 */
function validateSeverity(severity) {
  const allowed = ['critical', 'high', 'medium', 'low'];
  const normalized = (severity || '').toLowerCase();
  return allowed.includes(normalized) ? normalized : 'medium';
}

/**
 * Sanitizes a string field:
 *   - Ensures it's a string
 *   - Truncates to maxLength
 *   - Strips HTML tags (XSS prevention for React rendering)
 */
function sanitizeString(value, maxLength) {
  if (typeof value !== 'string') value = String(value);
  // Strip HTML tags — vulnerableCode could contain <script> etc.
  value = value.replace(/<[^>]*>/g, '');
  return value.slice(0, maxLength);
}

/**
 * Maps file extension to human-readable language name.
 * Used in prompt construction to give Gemini language context.
 */
function getLanguageName(extension) {
  const map = {
    '.js':   'JavaScript',
    '.jsx':  'JavaScript (React)',
    '.ts':   'TypeScript',
    '.tsx':  'TypeScript (React)',
    '.py':   'Python',
    '.java': 'Java',
    '.go':   'Go',
    '.rb':   'Ruby',
    '.php':  'PHP',
    '.cs':   'C#',
    '.cpp':  'C++',
    '.rs':   'Rust',
    '.sql':  'SQL',
    '.sh':   'Shell Script',
    '.yaml': 'YAML',
    '.yml':  'YAML',
    '.json': 'JSON',
    '.env':  'Environment Config',
    '.md':   'Markdown',
  };
  return map[extension?.toLowerCase()] || 'Unknown';
}

// ─────────────────────────────────────────────
// MAIN EXPORT
// ─────────────────────────────────────────────

/**
 * Sends files to Gemini for security analysis and returns
 * a validated, normalized vulnerability report.
 *
 * @param {Array<{ path: string, extension: string, content: string }>} files
 * @param {{ fullName: string, language: string }} metadata
 * @returns {Promise<object>} — normalized report object
 */
export async function analyzeWithGemini(files, metadata) {
  console.log(`[gemini] Starting analysis: ${files.length} files`);

  // geminiService.js — updated generationConfig

const model = genAI.getGenerativeModel({
  model: MODEL_NAME,
  systemInstruction: SYSTEM_PROMPT,
  generationConfig: {
    temperature: 0,
    topP: 0.95,
    topK: 40,

    // Raise this — Gemini 1.5 Flash actually supports up to 8192
    // by default but you can request higher on some model versions.
    // The real fix is the schema below, but give yourself headroom.
    maxOutputTokens: 8192,

    responseMimeType: 'application/json',

    // THIS is the strongest lever you have.
    // responseSchema forces Gemini to structurally obey the shape —
    // it literally cannot add fields outside this schema.
    // This is far more reliable than prompt instructions alone.
   responseSchema: {
  type: 'object',
  properties: {
    summary: {
      type: 'object',
      properties: {
        critical: { type: 'number' },
        high: { type: 'number' },
        medium: { type: 'number' },
        low: { type: 'number' },
        totalIssues: { type: 'number' },
        truncated: { type: 'boolean' }
      }
    },

    vulnerabilities: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          severity: { type: 'string' },
          category: { type: 'string' },
          categoryName: { type: 'string' },
          file: { type: 'string' },
          lineNumber: { type: 'number' },
          shortDescription: { type: 'string' },
          confidence: { type: 'string' },
          vulnerableCode: { type: 'string' },
          impact : {type : 'string'},
          // remediation : {type : 'string'},
        },

        required: [
          'id',
          'title',
          'severity',
          'category',
          'file',
          'shortDescription'
        ]
      }
    }
  },

  required: [
    'summary',
    'vulnerabilities'
  ]
  },
  },
});


  // Build the structured user message
  const userMessage = buildUserMessage(files, metadata);

  console.log(`[gemini] Sending request to ${MODEL_NAME}...`);
  const startTime = Date.now();

  let response;
  try {
    const result = await model.generateContent(userMessage);
    const candidate = result.response.candidates?.[0];

    if (candidate?.finishReason === 'MAX_TOKENS') {
    throw new AppError(
    'AI response exceeded output limit. Reduce findings or analyze fewer files.',
    500,
    'GEMINI_RESPONSE_TRUNCATED'
    );
  }
    console.log(
      JSON.stringify(result.response, null, 2)
    );
    console.log(
  result.response.candidates?.[0]?.finishReason
    );
    response = result.response;
  } catch (err) {
    console.error('[gemini] API call failed:', err.message);

    // Handle specific Gemini error types
    if (err.message?.includes('quota')) {
      throw new AppError(
        'AI analysis quota exceeded. Please try again later.',
        429,
        'GEMINI_QUOTA_EXCEEDED'
      );
    }

    if (err.message?.includes('blocked') || err.message?.includes('safety')) {
      throw new AppError(
        'Repository content was blocked by AI safety filters.',
        422,
        'GEMINI_CONTENT_BLOCKED'
      );
    }

    if (err.message?.includes('400')) {
  throw new AppError(
    'Invalid Gemini response schema configuration.',
    500,
    'GEMINI_SCHEMA_ERROR'
  );
  }

    throw new AppError(
      'AI analysis service is temporarily unavailable.',
      503,
      'GEMINI_UNAVAILABLE'
    );
    // if (err instanceof AppError) {
    // throw err;
    // }
  }

  const elapsed = Date.now() - startTime;
  console.log(`[gemini] Response received in ${elapsed}ms`);

  // Extract raw text from response
  const rawText = response.text();

  if (!rawText || rawText.trim().length === 0) {
    throw new AppError(
      'AI analysis returned an empty response.',
      500,
      'GEMINI_EMPTY_RESPONSE'
    );
  }

  

  // consoleeeeee
  console.log("Length:", rawText.length);
console.log("First 100 chars:");
console.log(rawText.slice(0, 300));
console.log("...");
console.log(rawText.slice(-1000));

  // Parse, validate, and normalize the response
  const report = parseGeminiResponse(rawText);

  console.log(
    `[gemini] Analysis complete: ` +
    `${report.summary.critical} critical, ` +
    `${report.summary.high} high, ` +
    `${report.summary.medium} medium, ` +
    `${report.summary.low} low`
  );

  console.log(JSON.stringify(report, null, 2));

  return report;
 }

