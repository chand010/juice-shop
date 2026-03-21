/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'
import config from 'config'
import pug from 'pug'
import fs from 'node:fs/promises'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'

const entities = new Entities()

function favicon () {
  return utils.extractFilename(config.get('application.favicon'))
}

export function getUserProfile () {
  return async (req: Request, res: Response, next: NextFunction) => {
    let template: string
    try {
      template = await fs.readFile('views/userProfile.pug', { encoding: 'utf-8' })
    } catch (err) {
      next(err)
      return
    }

    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress)); return
    }

    let user: UserModel | null
    try {
      user = await UserModel.findByPk(loggedInUser.data.id)
    } catch (error) {
      next(error)
      return
    }

    if (!user) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    // ✅ FIX 1: Remove eval() — RCE via username
    // ❌ Before: if username matches #{...}, extract code and call eval(code)
    //   attacker sets username to #{process.mainModule.require('child_process').execSync('whoami')}
    //   → arbitrary command execution on the server
    // ✅ After: never execute username as code — always escape it
    let username = user.username
    username = '\\' + (username ?? '')

    // ✅ FIX 2: encode username before injecting into pug template — prevents SSTI
    // ❌ Before: template.replace(/_username_/g, username) — raw username in pug template
    //   attacker sets username to: #{root.process.mainModule.require('child_process').execSync('id')}
    //   → pug evaluates it as JS during pug.compile(template) → RCE
    // ✅ After: HTML-encode username so pug treats it as plain text, never as code
    const safeUsername = username ? entities.encode(username) : ''

    const themeKey = config.get<string>('application.theme') as keyof typeof themes
    const theme = themes[themeKey] || themes['bluegrey-lightgreen']

    if (safeUsername) {
      template = template.replace(/_username_/g, safeUsername)
    }
    template = template.replace(/_emailHash_/g, security.hash(user?.email))
    template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
    template = template.replace(/_favicon_/g, favicon())
    template = template.replace(/_bgColor_/g, theme.bgColor)
    template = template.replace(/_textColor_/g, theme.textColor)
    template = template.replace(/_navColor_/g, theme.navColor)
    template = template.replace(/_primLight_/g, theme.primLight)
    template = template.replace(/_primDark_/g, theme.primDark)
    template = template.replace(/_logo_/g, utils.extractFilename(config.get('application.logo')))

    try {
      const fn = pug.compile(template)

      // ✅ FIX 3: CSP header injection via profileImage
      // ❌ Before: CSP = `img-src 'self' ${user?.profileImage}; script-src ...`
      //   attacker sets profileImage to: x; script-src 'unsafe-inline'
      //   → injects their own CSP directives, bypassing script-src restrictions
      // ✅ After: extract only the filename/URL, strip any semicolons or CSP metacharacters
      const safeProfileImage = (user?.profileImage ?? '').replace(/[;'"\\]/g, '')
      const CSP = `img-src 'self' ${safeProfileImage}; script-src 'self' 'unsafe-eval'`

      challengeUtils.solveIf(challenges.usernameXssChallenge, () => {
        return username && user?.profileImage.match(/;[ ]*script-src(.)*'unsafe-inline'/g) !== null && utils.contains(username, '<script>alert(`xss`)</script>')
      })

      res.set({
        'Content-Security-Policy': CSP
      })

      res.send(fn(user))
    } catch (err) {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}
