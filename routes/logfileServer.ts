/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

// ✅ FIX: Resolve the allowed directory once at module load time.
const LOGS_ROOT = path.resolve('logs')

// ✅ FIX: Restrict serving to expected log file extensions only.
// This is a defence-in-depth measure — the jail check below is the primary
// control, but limiting extensions reduces the blast radius if the jail
// were ever bypassed or misconfigured.
const ALLOWED_EXTENSIONS = new Set(['.log', '.txt'])

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // ✅ FIX: Validate input is a non-empty string before any path operation.
    if (!file || typeof file !== 'string') {
      res.status(400)
      next(new Error('Invalid file parameter'))
      return
    }

    if (!file.includes('/')) {
      // ✅ FIX: Directory jail — resolve the full path and assert it remains
      // inside LOGS_ROOT before serving.
      //
      // ❌ Before: res.sendFile(path.resolve('logs/', file)) with only a
      //    forward-slash check. Bypasses include:
      //    - URL-encoded traversal: %2e%2e%5cpasswd, ..%2fetc%2fpasswd
      //      Express decodes these before params.file is set, so the literal
      //      '/' check never fires but path.resolve() sees the traversal.
      //    - Backslash traversal on Windows: ..\secrets.txt
      //    - Overlong UTF-8 sequences decoded by some middleware stacks
      //
      // ✅ After: path.resolve() normalises all traversal sequences into a
      //    canonical absolute path first. The startsWith check then guarantees
      //    the result is strictly inside LOGS_ROOT regardless of how the input
      //    was encoded.
      const resolvedPath = path.resolve(LOGS_ROOT, file)
      if (!resolvedPath.startsWith(LOGS_ROOT + path.sep) && resolvedPath !== LOGS_ROOT) {
        res.status(403)
        next(new Error('Path traversal detected!'))
        return
      }

      // ✅ FIX: Extension allowlist — only serve recognised log file types.
      const ext = path.extname(resolvedPath).toLowerCase()
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        res.status(403)
        next(new Error('Only .log and .txt files are served from this endpoint'))
        return
      }

      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
