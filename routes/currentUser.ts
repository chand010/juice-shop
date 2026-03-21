/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'

// ✅ FIX: Define an explicit allowlist of fields that may be returned.
// ❌ Before: user?.data[field] where `field` came directly from req.query.fields
//   - Allows ?fields=__proto__     → prototype pollution
//   - Allows ?fields=password      → leaks password hash
//   - Allows ?fields=totpSecret    → leaks 2FA secret
//   - Allows ?fields=constructor   → object traversal
// ✅ After: field access is restricted to literal property names in ALLOWED_FIELDS.
//   Unrecognised field names are silently ignored.
const ALLOWED_FIELDS = new Set<string>(['id', 'email', 'lastLoginIp', 'profileImage'])

export function retrieveLoggedInUser () {
  return (req: Request, res: Response) => {
    let user
    let response: any
    const emptyUser = { id: undefined, email: undefined, lastLoginIp: undefined, profileImage: undefined }
    try {
      if (security.verify(req.cookies.token)) {
        user = security.authenticatedUsers.get(req.cookies.token)

        const fieldsParam = req.query?.fields as string | undefined
        const requestedFields = fieldsParam ? fieldsParam.split(',').map(f => f.trim()) : []

        let baseUser: any = {}

        if (requestedFields.length > 0) {
          // ✅ FIX: Only copy fields that are explicitly in ALLOWED_FIELDS.
          // Use if/else if with literal property access — no bracket notation on user input.
          for (const field of requestedFields) {
            if (!ALLOWED_FIELDS.has(field)) {
              // Silently skip any field not in the allowlist (e.g. __proto__, password, totpSecret)
              continue
            }
            // Access via literal property names only — never via user-supplied key
            if (field === 'id') baseUser.id = user?.data?.id
            else if (field === 'email') baseUser.email = user?.data?.email
            else if (field === 'lastLoginIp') baseUser.lastLoginIp = user?.data?.lastLoginIp
            else if (field === 'profileImage') baseUser.profileImage = user?.data?.profileImage
          }
        } else {
          // Default: return all standard (non-sensitive) fields
          baseUser = {
            id: user?.data?.id,
            email: user?.data?.email,
            lastLoginIp: user?.data?.lastLoginIp,
            profileImage: user?.data?.profileImage
          }
        }

        response = { user: baseUser }
      } else {
        response = { user: emptyUser }
      }
    } catch (err) {
      response = { user: emptyUser }
    }

    // Solve passwordHashLeakChallenge when password field is included in response.
    // With the allowlist in place this can never be triggered via the fields param,
    // but the check is kept for completeness.
    challengeUtils.solveIf(challenges.passwordHashLeakChallenge, () => response?.user?.password)

    if (req.query.callback === undefined) {
      res.json(response)
    } else {
      challengeUtils.solveIf(challenges.emailLeakChallenge, () => { return true })
      res.jsonp(response)
    }
  }
}
