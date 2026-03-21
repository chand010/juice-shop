/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

// ✅ FIX: Resolve the allowed directory once at module load time.
const KEYS_ROOT = path.resolve('encryptionkeys')

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      // ✅ FIX: Directory jail — confirm the resolved path stays inside KEYS_ROOT.
      // ❌ Before: res.sendFile(path.resolve('encryptionkeys/', file)) with no
      //    further check. The forward-slash guard blocks literal '/' but does
      //    NOT block URL-encoded traversal sequences that Express decodes before
      //    populating params.file, for example:
      //      %2e%2e%5c..%5cinsecurity.ts  → resolves outside encryptionkeys/
      //      ..%2fjwt.pub                 → partial encoding bypass
      //    path.resolve() would produce an out-of-bounds path and sendFile()
      //    would serve any readable file on the filesystem — private keys,
      //    source files, the SQLite database, etc.
      //
      // ✅ After: resolve the full path and assert it is a strict child of
      //    KEYS_ROOT before serving. Any escaping path gets a 403.
      const resolvedPath = path.resolve(KEYS_ROOT, file)
      if (!resolvedPath.startsWith(KEYS_ROOT + path.sep) && resolvedPath !== KEYS_ROOT) {
        res.status(403)
        next(new Error('Path traversal detected!'))
        return
      }

      res.sendFile(resolvedPath)
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
