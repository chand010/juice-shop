import fs from 'node:fs/promises'
import path from 'node:path'
import logger from './logger'

export const SNIPPET_PATHS = Object.freeze(['./server.ts', './routes', './lib', './data', './data/static/web3-snippets', './frontend/src/app', './models'])

interface FileMatch {
  path: string
  content: string
}

interface CachedCodeChallenge {
  snippet: string
  vulnLines: number[]
  neutralLines: number[]
}

// ✅ FIX: Escape all special regex metacharacters in challengeKey before
// interpolating it into any RegExp constructor or string-based match() call.
//
// ❌ Before: new RegExp(`...${challengeKey}`) and source.match(`...${challengeKey}`)
//    challengeKey is extracted from file content, so a crafted source file
//    could inject a ReDoS payload, e.g.:
//      vuln-code-snippet start ((a+)+)$
//    The RegExp engine would backtrack catastrophically on a mismatched input,
//    blocking the Node.js event loop indefinitely (single-threaded CPU spin).
//
// ✅ After: escapeRegExp() converts every special character to its literal
//    escaped form, so the key is always matched as a plain string, never as
//    a pattern. This is the approach recommended by MDN and used by the
//    widely-adopted escape-string-regexp npm package.
function escapeRegExp (str: string): string {
  // Escapes: \ ^ $ . | ? * + ( ) [ ] { }
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

// Validate that the key is purely alphanumeric + hyphens/underscores before
// using it. All legitimate challenge keys in the codebase match this pattern;
// anything else is a sign of a malformed or malicious snippet file.
function validateChallengeKey (key: string): boolean {
  return /^[\w-]+$/.test(key)
}

export const findFilesWithCodeChallenges = async (paths: readonly string[]): Promise<FileMatch[]> => {
  const matches = []
  for (const currPath of paths) {
    if ((await fs.lstat(currPath)).isDirectory()) {
      const files = await fs.readdir(currPath)
      const moreMatches = await findFilesWithCodeChallenges(
        files.map(file => path.resolve(currPath, file))
      )
      matches.push(...moreMatches)
    } else {
      try {
        const code = await fs.readFile(currPath, 'utf8')
        if (
          // strings are split so that it doesn't find itself...
          code.includes('// vuln-code' + '-snippet start') ||
          code.includes('# vuln-code' + '-snippet start')
        ) {
          matches.push({ path: currPath, content: code })
        }
      } catch (e) {
        logger.warn(`File ${currPath} could not be read. it might have been moved or deleted. If coding challenges are contained in the file, they will not be available.`)
      }
    }
  }

  return matches
}

function getCodeChallengesFromFile (file: FileMatch) {
  const fileContent = file.content

  // get all challenges which are in the file by a regex capture group
  const challengeKeyRegex = /[/#]{0,2} vuln-code-snippet start (?<challenges>.*)/g
  const challenges = [...fileContent.matchAll(challengeKeyRegex)]
    .flatMap(match => match.groups?.challenges?.split(' ') ?? [])
    .filter(Boolean)

  return challenges.map((challengeKey) => getCodingChallengeFromFileContent(fileContent, challengeKey))
}

function getCodingChallengeFromFileContent (source: string, challengeKey: string) {
  // ✅ FIX: Validate then escape challengeKey before any RegExp/match use.
  if (!validateChallengeKey(challengeKey)) {
    throw new BrokenBoundary(`Invalid challenge key (contains disallowed characters): ${challengeKey}`)
  }
  const safeKey = escapeRegExp(challengeKey)

  // ✅ Use safeKey (escaped) everywhere challengeKey was previously interpolated raw.
  const snippets = source.match(`[/#]{0,2} vuln-code-snippet start.*${safeKey}([^])*vuln-code-snippet end.*${safeKey}`)
  if (snippets == null) {
    throw new BrokenBoundary('Broken code snippet boundaries for: ' + challengeKey)
  }
  let snippet = snippets[0] // TODO Currently only a single code snippet is supported
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet start.*[\r\n]{0,2}/g, '')
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet end.*/g, '')
  snippet = snippet.replace(/.*[/#]{0,2} vuln-code-snippet hide-line[\r\n]{0,2}/g, '')
  snippet = snippet.replace(/.*[/#]{0,2} vuln-code-snippet hide-start([^])*[/#]{0,2} vuln-code-snippet hide-end[\r\n]{0,2}/g, '')
  snippet = snippet.trim()

  let lines = snippet.split('\r\n')
  if (lines.length === 1) lines = snippet.split('\n')
  if (lines.length === 1) lines = snippet.split('\r')
  const vulnLines = []
  const neutralLines = []
  for (let i = 0; i < lines.length; i++) {
    // ✅ Use safeKey in per-line RegExp constructors.
    if (new RegExp(`vuln-code-snippet vuln-line.*${safeKey}`).exec(lines[i]) != null) {
      vulnLines.push(i + 1)
    } else if (new RegExp(`vuln-code-snippet neutral-line.*${safeKey}`).exec(lines[i]) != null) {
      neutralLines.push(i + 1)
    }
  }
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet vuln-line.*/g, '')
  snippet = snippet.replace(/\s?[/#]{0,2} vuln-code-snippet neutral-line.*/g, '')
  return { challengeKey, snippet, vulnLines, neutralLines }
}

class BrokenBoundary extends Error {
  constructor (message: string) {
    super(message)
    this.name = 'BrokenBoundary'
    this.message = message
  }
}

// dont use directly, use getCodeChallenges getter
let _internalCodeChallenges: Map<string, CachedCodeChallenge> | null = null
export async function getCodeChallenges (): Promise<Map<string, CachedCodeChallenge>> {
  if (_internalCodeChallenges === null) {
    _internalCodeChallenges = new Map<string, CachedCodeChallenge>()
    const filesWithCodeChallenges = await findFilesWithCodeChallenges(SNIPPET_PATHS)
    for (const fileMatch of filesWithCodeChallenges) {
      for (const codeChallenge of getCodeChallengesFromFile(fileMatch)) {
        _internalCodeChallenges.set(codeChallenge.challengeKey, {
          snippet: codeChallenge.snippet,
          vulnLines: codeChallenge.vulnLines,
          neutralLines: codeChallenge.neutralLines
        })
      }
    }
  }
  return _internalCodeChallenges
}
