/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

// ✅ FIX: Sanitize BASE_PATH before using it in HTTP headers.
// ❌ Before: process.env.BASE_PATH used raw — if it ever contains CRLF
//   sequences (\r\n) an attacker with control over env could inject
//   arbitrary response headers (HTTP header injection).
function safeBasePath (): string {
  return (process.env.BASE_PATH ?? '').replace(/[\r\n]/g, '')
}

export function updateUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)

    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        next(new Error('User not found'))
        return
      }

      challengeUtils.solveIf(challenges.csrfChallenge, () => {
        return ((req.headers.origin?.includes('://htmledit.squarefree.com')) ??
          (req.headers.referer?.includes('://htmledit.squarefree.com'))) &&
          req.body.username !== user.username
      })

      // ✅ FIX: Sanitize the username before persisting it and embedding
      // it in the JWT payload.
      // ❌ Before: req.body.username stored as-is — script tags would
      //   cause stored XSS when rendered; arbitrary chars appear in JWT claims.
      // ✅ After: restrict to safe character set, trim, cap length.
      //   Adjust the regex to match your username policy.
      const rawUsername = String(req.body.username ?? '')
      const safeUsername = rawUsername.replace(/[^\w\s.\-]/g, '').trim().substring(0, 255)

      const savedUser = await user.update({ username: safeUsername })
      const userWithStatus = utils.queryResultToJson(savedUser)

      // updatedToken is server-signed — the user cannot forge it.
      // The semgrep finding flags that user input (username) flows into
      // the JWT payload and then into res.cookie. Both mitigations are
      // applied: the username is sanitized above, and the cookie carries
      // mandatory security attributes below.
      const updatedToken = security.authorize(userWithStatus)
      security.authenticatedUsers.put(updatedToken, userWithStatus)

      // ✅ FIX: Set cookie with security attributes.
      // ❌ Before: res.cookie('token', updatedToken)
      //   - No httpOnly  → JS on the page can read the token (XSS theft)
      //   - No secure    → Token sent over plain HTTP in non-HTTPS envs
      //   - No sameSite  → Token sent on cross-site requests (CSRF vector)
      res.cookie('token', updatedToken, {
        httpOnly: true,                                 // prevents JS access
        secure: process.env.NODE_ENV === 'production',  // HTTPS-only in prod
        sameSite: 'strict'                              // blocks CSRF
      })

      const base = safeBasePath()
      res.location(base + '/profile')
      res.redirect(base + '/profile')
    } catch (error) {
      next(error)
    }
  }
}
