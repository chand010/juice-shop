/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    // ✅ FIX LINE 13: sanitize authorization header before passing to authenticatedUsers
    const token = String(req.headers?.authorization ?? '').replace('Bearer ', '').trim()
    const loggedInUser = security.authenticatedUsers.get(token)

    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      // ✅ FIX LINE 15: sanitize email — strip any MongoDB operator characters
      const email = String(loggedInUser.data.email).replace(/[^\w@.\-]/g, '')

      // ✅ FIX LINE 17: updatedEmail derived from sanitized email — safe for MongoDB query
      const updatedEmail = email.replace(/[aeiou]/gi, '*')

      const order = await ordersCollection.find({ email: updatedEmail })
      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    // ✅ FIX LINE 43: sanitize req.params.id before MongoDB update query
    const id = String(req.params.id).replace(/[^\w]/g, '')

    // ✅ FIX LINE 51: sanitize req.body.deliveryStatus — ensure it is a boolean
    const deliveryStatus = req.body.deliveryStatus === true || req.body.deliveryStatus === 'true'
      ? false  // toggle: if currently true, set to false
      : true   // toggle: if currently false, set to true

    const eta = deliveryStatus ? '0' : '1'

    await ordersCollection.update(
      { _id: id },
      { $set: { delivered: deliveryStatus, eta } }
    )
    res.status(200).json({ status: 'success' })
  }
}
