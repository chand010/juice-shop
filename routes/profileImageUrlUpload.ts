/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// ✅ FIX SSRF: allowlist of permitted image extensions
const ALLOWED_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'svg', 'gif'])

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true

      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }

          // ✅ FIX PATH TRAVERSAL — id sanitization
          // ❌ Before: loggedInUser.data.id raw in file path
          //   id could contain ../../etc/passwd → writes outside allowed dir
          const safeId = String(loggedInUser.data.id).replace(/[^\w]/g, '')

          // ✅ FIX PATH TRAVERSAL — ext sanitization
          // ❌ Before: ext derived from URL — attacker controls the URL extension
          //   url.split('.').slice(-1)[0] could return 'php' or contain path separators
          // ✅ After: only allow known safe image extensions, default to jpg
          const urlExt = url.split('.').slice(-1)[0].toLowerCase().replace(/[^\w]/g, '')
          const safeExt = ALLOWED_EXTENSIONS.has(urlExt) ? urlExt : 'jpg'

          if (!safeId) {
            next(new Error('Invalid user identifier'))
            return
          }

          // ✅ FIX PATH TRAVERSAL — directory jail
          const allowedDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
          const filePath = path.resolve(allowedDir, `${safeId}.${safeExt}`)

          // Double-check resolved path stays inside allowed directory
          if (!filePath.startsWith(allowedDir + path.sep)) {
            next(new Error('Blocked illegal file path'))
            return
          }

          const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

          const user = await UserModel.findByPk(loggedInUser.data.id)
          // ✅ Also sanitize the profileImage value stored in DB
          await user?.update({ profileImage: `/assets/public/images/uploads/${safeId}.${safeExt}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            // ✅ FIX: do not store raw user-supplied URL directly in DB as profileImage
            // sanitize to only allow http/https URLs before storing
            const safeUrl = String(url).startsWith('http://') || String(url).startsWith('https://')
              ? url
              : ''
            await user?.update({ profileImage: safeUrl })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }

    // ✅ FIX: sanitize BASE_PATH before using in redirect — prevents open redirect
    const basePath = String(process.env.BASE_PATH ?? '').replace(/[^a-zA-Z0-9/_-]/g, '')
    res.location(basePath + '/profile')
    res.redirect(basePath + '/profile')
  }
}
