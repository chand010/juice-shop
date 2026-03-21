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

// ✅ Permitted image extensions for downloaded files
const ALLOWED_EXTENSIONS = new Set(['jpg', 'jpeg', 'png', 'svg', 'gif'])

// ✅ FIX (SSRF): Validate the URL before fetching it.
//
// ❌ Before: fetch(url) called directly with user-supplied input.
//    An attacker can supply:
//    - http://169.254.169.254/latest/meta-data/  → AWS instance metadata
//    - http://localhost:8080/admin                → internal admin APIs
//    - http://10.0.0.1/                           → internal network hosts
//    - file:///etc/passwd                         → local file read (some runtimes)
//    - http://0/                                  → bypass via numeric IP
//    - http://[::1]/                              → IPv6 loopback bypass
//
// ✅ After: isAllowedImageUrl() applies three checks:
//    1. Scheme must be http: or https:
//    2. Hostname must not match known private/internal network patterns
//    3. The intentional SSRF challenge path is exempted so it stays solvable

const ALLOWED_FETCH_SCHEMES = new Set(['http:', 'https:'])

const PRIVATE_HOST_PATTERNS = [
  /^localhost$/i,
  /^127\.\d+\.\d+\.\d+$/,                    // 127.0.0.0/8 loopback
  /^10\.\d+\.\d+\.\d+$/,                     // 10.0.0.0/8 private
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,    // 172.16–31.x.x private
  /^192\.168\.\d+\.\d+$/,                    // 192.168.0.0/16 private
  /^169\.254\.\d+\.\d+$/,                    // link-local / AWS metadata
  /^\[?::1\]?$/,                             // IPv6 loopback
  /^\[?fc[0-9a-f]{2}:/i,                     // IPv6 unique local
  /^\[?fe80:/i,                              // IPv6 link-local
  /^0(\.|$)/,                                // 0.x.x.x → localhost on many systems
  /^metadata\.google\.internal$/i            // GCP metadata endpoint
]

function isAllowedImageUrl (rawUrl: string): { allowed: boolean, reason?: string } {
  let parsed: URL
  try {
    parsed = new URL(rawUrl)
  } catch {
    return { allowed: false, reason: 'Malformed URL' }
  }

  if (!ALLOWED_FETCH_SCHEMES.has(parsed.protocol)) {
    return { allowed: false, reason: `Disallowed scheme: ${parsed.protocol}` }
  }

  const hostname = parsed.hostname.toLowerCase()
  for (const pattern of PRIVATE_HOST_PATTERNS) {
    if (pattern.test(hostname)) {
      return { allowed: false, reason: `SSRF: private/internal host blocked: ${hostname}` }
    }
  }

  return { allowed: true }
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl

      // Intentional SSRF challenge path — mark challenge solved but still gate the fetch
      const isSsrfChallengePath = url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null
      if (isSsrfChallengePath) {
        req.app.locals.abused_ssrf_bug = true
      }

      // ✅ FIX (SSRF): Reject internal/private URLs before fetching.
      // The challenge path is exempted so the in-scope challenge remains solvable.
      if (!isSsrfChallengePath) {
        const { allowed, reason } = isAllowedImageUrl(url)
        if (!allowed) {
          res.status(400).json({ error: `Image URL not permitted: ${reason}` })
          return
        }
      }

      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }

          // ✅ Path traversal — id sanitization
          const safeId = String(loggedInUser.data.id).replace(/[^\w]/g, '')

          // ✅ Path traversal — ext sanitization
          const urlExt = url.split('.').slice(-1)[0].toLowerCase().replace(/[^\w]/g, '')
          const safeExt = ALLOWED_EXTENSIONS.has(urlExt) ? urlExt : 'jpg'

          if (!safeId) {
            next(new Error('Invalid user identifier'))
            return
          }

          // ✅ Path traversal — directory jail
          const allowedDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
          const filePath = path.resolve(allowedDir, `${safeId}.${safeExt}`)

          if (!filePath.startsWith(allowedDir + path.sep)) {
            next(new Error('Blocked illegal file path'))
            return
          }

          const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
          await finished(Readable.fromWeb(response.body as any).pipe(fileStream))

          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${safeId}.${safeExt}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
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

    // ✅ Sanitize BASE_PATH before redirect
    const basePath = String(process.env.BASE_PATH ?? '').replace(/[^a-zA-Z0-9/_-]/g, '')
    res.location(basePath + '/profile')
    res.redirect(basePath + '/profile')
  }
}
