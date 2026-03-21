/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'

export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req)

    // ✅ FIX: require authentication before any update
    if (!user?.data?.email) {
      return res.status(401).json({ error: 'Unauthorized' })
    }

    // ✅ FIX: sanitize id — prevents NoSQL operator injection e.g. { $gt: "" }
    const id = String(req.body.id).replace(/[^\w]/g, '')

    // ✅ FIX: sanitize message — strip HTML/script tags to prevent XSS in stored reviews
    const message = String(req.body.message).replace(/[<>]/g, '')

    if (!id || !message) {
      return res.status(400).json({ error: 'Invalid parameters' })
    }

    db.reviewsCollection.update(
      // ✅ FIX: use sanitized id + scope update to authenticated user's own reviews
      // prevents forged review — user can only update reviews they authored
      { _id: id, author: user.data.email },
      { $set: { message } },
      // ✅ FIX: multi: false — only ever update ONE document at a time
      // multi: true allowed a single request to overwrite ALL reviews at once
      { multi: false }
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 })
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 })
        res.json(result)
      }, (err: unknown) => {
        // ✅ FIX: never leak raw error to client — log server side only
        console.error('Error updating review:', err)
        res.status(500).json({ error: 'Internal server error' })
      })
  }
}
