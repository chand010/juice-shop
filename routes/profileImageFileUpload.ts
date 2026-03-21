/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs/promises'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import fileType from 'file-type'

import logger from '../lib/logger'
import * as utils from '../lib/utils'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'

export function profileImageFileUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const file = req.file
    const buffer = file?.buffer
    if (buffer === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }

    const uploadedFileType = await fileType.fromBuffer(buffer)
    if (uploadedFileType === undefined) {
      res.status(500)
      next(new Error('Illegal file type'))
      return
    }

    if (uploadedFileType === null || !utils.startsWith(uploadedFileType.mime, 'image')) {
      res.status(415)
      next(new Error(`Profile image upload does not accept this file type${uploadedFileType ? (': ' + uploadedFileType.mime) : '.'}`))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    // ✅ FIX PATH TRAVERSAL:
    // ❌ Before: id and ext flowed directly into file path with no sanitization
    //   loggedInUser.data.id could contain ../../../etc/passwd
    //   uploadedFileType.ext could contain path separators
    // ✅ After:
    //   1. Strip non-word characters from both id and ext
    //   2. Resolve final path and confirm it stays inside allowed directory
    const safeId = String(loggedInUser.data.id).replace(/[^\w]/g, '')
    const safeExt = String(uploadedFileType.ext).replace(/[^\w]/g, '')

    if (!safeId || !safeExt) {
      res.status(400)
      next(new Error('Invalid file identifier or extension'))
      return
    }

    const allowedDir = path.resolve('frontend/dist/frontend/assets/public/images/uploads')
    const filePath = path.resolve(allowedDir, `${safeId}.${safeExt}`)

    // Double-check resolved path is still inside allowed directory
    if (!filePath.startsWith(allowedDir + path.sep)) {
      res.status(400)
      next(new Error('Blocked illegal file path'))
      return
    }

    try {
      await fs.writeFile(filePath, buffer)
    } catch (err) {
      logger.warn('Error writing file: ' + (err instanceof Error ? err.message : String(err)))
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (user != null) {
        // ✅ Also sanitize the profileImage value stored in DB
        await user.update({ profileImage: `assets/public/images/uploads/${safeId}.${safeExt}` })
      }
    } catch (error) {
      next(error)
    }

    const basePath = String(process.env.BASE_PATH ?? '').replace(/[^a-zA-Z0-9/_-]/g, '')
    res.location(basePath + '/profile')
    res.redirect(basePath + '/profile')
  }
}
