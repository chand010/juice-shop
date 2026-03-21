/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

// ✅ FIX: Resolve the quarantine directory once at module load time.
const QUARANTINE_ROOT = path.resolve('ftp/quarantine')

// ✅ FIX: Only serve file types expected in the quarantine folder.
// Adjust this set to match your actual quarantine file naming convention.
const ALLOWED_EXTENSIONS = new Set(['.md', '.pdf', '.gg', '.bak', '.yml', '.pyc', '.kdbx'])

export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // ✅ FIX: Validate input is a non-empty string before any path operation.
    if (!file || typeof file !== 'string') {
      res.status(400)
      next(new Error('Invalid file parameter'))
      return
    }

    if (!file.includes('/')) {
      // ✅ FIX: Directory jail — resolve the full path and assert it remains
      // strictly inside QUARANTINE_ROOT before serving.
      //
      // ❌ Before: res.sendFile(path.resolve('ftp/quarantine/', file)) with
      //    only a forward-slash check. Bypasses include:
      //    - URL-encoded traversal: %2e%2e%5c, ..%2f
      //      Express decodes params.file before the handler runs, so the
      //      literal '/' check never fires but path.resolve() sees the escape.
      //    - Backslash on Windows: ..\secrets.txt
      //    - Overlong / double-encoded sequences decoded by upstream middleware
      //
      // ✅ After: path.resolve() canonicalises all sequences into an absolute
      //    path first. The startsWith check then guarantees the result stays
      //    inside QUARANTINE_ROOT regardless of input encoding.
      const resolvedPath = path.resolve(QUARANTINE_ROOT, file)
      if (!resolvedPath.startsWith(QUARANTINE_ROOT + path.sep) && resolvedPath !== QUARANTINE_ROOT) {
        res.status(403)
        next(new Error('Path traversal detected!'))
        return
      }

      // ✅ FIX: Extension allowlist — only serve recognised quarantine file types.
      const ext = path.extname(resolvedPath).toLowerCase()
      if (!ALLOWED_EXTENSIONS.has(ext)) {
        res.status(403)
        next(new Error('File type not permitted from quarantine endpoint'))
        return
      }

      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
