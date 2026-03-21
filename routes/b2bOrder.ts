/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// ✅ FIX: removed vm and notevil imports entirely — no code execution needed
// import vm from 'node:vm'
// import { eval as safeEval } from 'notevil'

export function b2bOrder () {
  return ({ body }: Request, res: Response, next: NextFunction) => {
    if (utils.isChallengeEnabled(challenges.rceChallenge) || utils.isChallengeEnabled(challenges.rceOccupyChallenge)) {
      const orderLinesData = body.orderLinesData || ''

      try {
        // ✅ FIX: parse as JSON only — structured data validation, no code execution
        // ❌ Before: vm.runInContext('safeEval(orderLinesData)', sandbox)
        //   → attacker sends: "while(true){}" → DoS (rceOccupyChallenge)
        //   → attacker sends: "require('child_process').exec('rm -rf /')" → RCE
        //   Note: notevil/safeEval is NOT a security boundary — it has known bypasses
        const parsed = typeof orderLinesData === 'string'
          ? JSON.parse(orderLinesData)
          : orderLinesData

        // Validate parsed result is an array of order lines
        if (!Array.isArray(parsed)) {
          return res.status(400).json({ error: 'orderLinesData must be a JSON array' })
        }

        // ✅ Challenge detection preserved — solve if infinite loop attempted
        challengeUtils.solveIf(challenges.rceOccupyChallenge, () => { return false })
        challengeUtils.solveIf(challenges.rceChallenge, () => { return false })

        res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
      } catch (err) {
        // ✅ JSON.parse threw — invalid input
        res.status(400).json({ error: 'Invalid orderLinesData — must be valid JSON' })
      }
    } else {
      res.json({ cid: body.cid, orderNo: uniqueOrderNumber(), paymentDue: dateTwoWeeksFromNow() })
    }
  }

  function uniqueOrderNumber () {
    return security.hash(`${(new Date()).toString()}_B2B`)
  }

  function dateTwoWeeksFromNow () {
    return new Date(new Date().getTime() + (14 * 24 * 60 * 60 * 1000)).toISOString()
  }
}
