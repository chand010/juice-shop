/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { type Review } from 'data/types'
import * as db from '../data/mongodb'
import * as utils from '../lib/utils'

// Blocking sleep function as in native MongoDB
// @ts-expect-error FIXME Type safety broken for global object
global.sleep = (time: number) => {
  // Ensure that users don't accidentally dos their servers for too long
  if (time > 2000) {
    time = 2000
  }
  const stop = new Date().getTime()
  while (new Date().getTime() < stop + time) {
    ;
  }
}

export function showProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    // ✅ FIX LINE 31: always cast id to a plain Number — no string concatenation
    // ❌ Before: used $where with string concat → allowed NoSQL JS injection
    //   db.reviewsCollection.find({ $where: 'this.product == ' + id })
    // ✅ After: use a standard equality query with a numeric id — $where removed entirely
    const id = Number(req.params.id)

    // Reject non-numeric ids immediately — prevents any injection attempt
    if (isNaN(id)) {
      res.status(400).json({ error: 'Invalid product id' })
      return
    }

    // ✅ FIX LINE 36: replace $where string concatenation with safe equality query
    // $where executes arbitrary JavaScript on the MongoDB server — never use with user input
    const t0 = new Date().getTime()

    db.reviewsCollection.find({ product: id }).then((reviews: Review[]) => {
      const t1 = new Date().getTime()
      challengeUtils.solveIf(challenges.noSqlCommandChallenge, () => { return (t1 - t0) > 2000 })
      const user = security.authenticatedUsers.from(req)
      for (let i = 0; i < reviews.length; i++) {
        if (user === undefined || reviews[i].likedBy.includes(user.data.email)) {
          reviews[i].liked = true
        }
      }
      res.json(utils.queryResultToJson(reviews))
    }, () => {
      res.status(400).json({ error: 'Wrong Params' })
    })
  }
}
