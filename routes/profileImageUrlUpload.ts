/*
 * Fixed: path traversal vulnerability via unsanitized key parameter
 */

import fs from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'
import { type NextFunction, type Request, type Response } from 'express'

import * as accuracy from '../lib/accuracy'
import * as challengeUtils from '../lib/challengeUtils'
import { type ChallengeKey } from 'models/challenge'

const FixesDir = path.resolve('data/static/codefixes')

interface codeFix {
  fixes: string[]
  correct: number
}

type cache = Record<string, codeFix>

const CodeFixes: cache = {}

export const readFixes = (key: string) => {
  // ✅ FIX PATH TRAVERSAL: sanitize key before using in any file path
  // ❌ Before: key used raw — attacker sends ../../etc/passwd → reads arbitrary files
  // ✅ After: strip everything except word chars and hyphens
  const safeKey = String(key).replace(/[^\w-]/g, '')

  if (!safeKey) {
    return { fixes: [], correct: -1 }
  }

  if (CodeFixes[safeKey]) {
    return CodeFixes[safeKey]
  }

  const files = fs.readdirSync(FixesDir)
  const fixes: string[] = []
  let correct: number = -1

  for (const file of files) {
    if (file.startsWith(`${safeKey}_`)) {
      // ✅ FIX: resolve and jail each file path inside FixesDir
      const filePath = path.resolve(FixesDir, file)
      if (!filePath.startsWith(FixesDir + path.sep)) {
        continue
      }
      const fix = fs.readFileSync(filePath).toString()
      const metadata = file.split('_')
      const number = metadata[1]
      fixes.push(fix)
      if (metadata.length === 3) {
        correct = parseInt(number, 10)
        correct--
      }
    }
  }

  CodeFixes[safeKey] = { fixes, correct }
  return CodeFixes[safeKey]
}

interface FixesRequestParams {
  key: string
}

interface VerdictRequestBody {
  key: ChallengeKey
  selectedFix: number
}

export const serveCodeFixes = () => (req: Request<FixesRequestParams, Record<string, unknown>, Record<string, unknown>>, res: Response, next: NextFunction) => {
  const key = req.params.key
  const fixData = readFixes(key)
  if (fixData.fixes.length === 0) {
    res.status(404).json({ error: 'No fixes found for the snippet!' })
    return
  }
  res.status(200).json({ fixes: fixData.fixes })
}

export const checkCorrectFix = () => async (req: Request<Record<string, unknown>, Record<string, unknown>, VerdictRequestBody>, res: Response, next: NextFunction) => {
  const key = req.body.key

  // ✅ FIX PATH TRAVERSAL: sanitize key before building .info.yml path
  // ❌ Before: './data/static/codefixes/' + key + '.info.yml'
  //   attacker sends key = '../../etc/passwd' → reads arbitrary files
  const safeKey = String(key).replace(/[^\w-]/g, '')

  const selectedFix = req.body.selectedFix
  const fixData = readFixes(safeKey)

  if (fixData.fixes.length === 0) {
    res.status(404).json({ error: 'No fixes found for the snippet!' })
  } else {
    let explanation
    const infoFilePath = path.resolve(FixesDir, `${safeKey}.info.yml`)

    // ✅ FIX: confirm .info.yml path is still inside FixesDir before reading
    if (
      infoFilePath.startsWith(FixesDir + path.sep) &&
      fs.existsSync(infoFilePath)
    ) {
      const codingChallengeInfos = yaml.load(fs.readFileSync(infoFilePath, 'utf8'))
      const selectedFixInfo = (codingChallengeInfos as any)?.fixes.find(({ id }: { id: number }) => id === selectedFix + 1)
      if (selectedFixInfo?.explanation) explanation = res.__(selectedFixInfo.explanation)
    }

    if (selectedFix === fixData.correct) {
      await challengeUtils.solveFixIt(safeKey as ChallengeKey)
      res.status(200).json({ verdict: true, explanation })
    } else {
      accuracy.storeFixItVerdict(safeKey as ChallengeKey, false)
      res.status(200).json({ verdict: false, explanation })
    }
  }
}
