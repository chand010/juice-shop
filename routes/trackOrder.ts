/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as utils from '../lib/utils'
import * as challengeUtils from '../lib/challengeUtils'
import { type Request, type Response } from 'express'
import * as db from '../data/mongodb'
import { challenges } from '../data/datacache'

export function trackOrder () {
  return (req: Request, res: Response) => {
    // ✅ FIX LINE 15: always sanitize id to a safe alphanumeric+dash string
    // ❌ Before: used utils.trunc() which still allowed special chars → $where injection
    // ✅ After: always strip non-word characters regardless of challenge flag
    const id = String(req.params.id).replace(/[^\w-]+/g, '')

    // Reject empty id after sanitization
    if (!id) {
      res.status(400).json({ error: 'Invalid order id' })
      return
    }

    challengeUtils.solveIf(challenges.reflectedXssChallenge, () => { return utils.contains(id, '<iframe src="javascript:alert(`xss`)">') })

    // ✅ FIX LINE 18: replace $where template literal with safe equality query
    // ❌ Before: { $where: `this.orderId === '${id}'` }
    //   → attacker could inject: ' || '1'=='1  to match all orders (NoSQL injection)
    //   → attacker could inject: '; sleep(2000);  to cause DoS
    // ✅ After: plain equality query — no JavaScript execution on MongoDB server
    db.ordersCollection.find({ orderId: id }).then((order: any) => {
      const result = utils.queryResultToJson(order)
      challengeUtils.solveIf(challenges.noSqlOrdersChallenge, () => { return result.data.length > 1 })
      if (result.data[0] === undefined) {
        result.data[0] = { orderId: id }
      }
      res.json(result)
    }, () => {
      res.status(400).json({ error: 'Wrong Param' })
    })
  }
}
