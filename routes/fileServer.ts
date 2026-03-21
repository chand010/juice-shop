/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

// ✅ FIX: Resolve the allowed directory once at module load time so every
// request can be checked against it without re-computing the absolute path.
const FTP_ROOT = path.resolve('ftp')

export function servePublicFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    if (file && (endsWithAllowlistedFileType(file) || (file === 'incident-support.kdbx'))) {
      file = security.cutOffPoisonNullByte(file)

      // ✅ FIX: Directory jail — confirm the resolved path is still inside FTP_ROOT.
      // ❌ Before: res.sendFile(path.resolve('ftp/', file)) with no further check.
      //    cutOffPoisonNullByte() removes the null byte, but the remaining filename
      //    could still contain encoded traversal sequences that survive the
      //    forward-slash check above, e.g.:
      //      %2e%2e%5cpasswd   → decoded by Express before params.file is set
      //      ..%2fpasswd       → similar bypass via partial encoding
      //    path.resolve() would then produce a path outside ftp/, and sendFile()
      //    would serve any readable file on the filesystem as long as its
      //    extension passed the allowlist check (e.g. a crafted ../lib/utils.md).
      //
      // ✅ After: resolve the final path and assert it starts with FTP_ROOT + sep.
      //    If the resolved path escapes the directory, return 403 immediately.
      //    The intentional null-byte / easter-egg challenges still work because
      //    those filenames resolve to paths inside ftp/ after cutOffPoisonNullByte.
      const resolvedPath = path.resolve(FTP_ROOT, file)
      if (!resolvedPath.startsWith(FTP_ROOT + path.sep) && resolvedPath !== FTP_ROOT) {
        res.status(403)
        next(new Error('Path traversal detected!'))
        return
      }

      challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
      verifySuccessfulPoisonNullByteExploit(file)

      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('Only .md and .pdf files are allowed!'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }

  function endsWithAllowlistedFileType (param: string) {
    return utils.endsWith(param, '.md') || utils.endsWith(param, '.pdf')
  }
}
