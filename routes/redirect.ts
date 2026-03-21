/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as utils from '../lib/utils'

// Allowed URL schemes for outbound redirects.
// javascript:, data:, vbscript: and similar pseudo-schemes must never be permitted.
const ALLOWED_SCHEMES = new Set(['http:', 'https:'])

export function performRedirect () {
  return ({ query }: Request, res: Response, next: NextFunction) => {
    const toUrl: string = query.to as string

    // ✅ FIX: Validate and parse toUrl before acting on it.
    // ❌ Before: toUrl passed to res.redirect() after only an includes()-based
    //    allowlist check — several bypass classes existed:
    //
    //    1. Scheme injection:
    //       ?to=javascript:alert(1)  or  ?to=data:text/html,<script>...
    //       → bypasses string-contains check, executes arbitrary JS in browser
    //
    //    2. URL-embedding bypass:
    //       ?to=https://evil.com?ref=https://github.com/juice-shop/juice-shop
    //       → toUrl.includes(allowedUrl) is TRUE because the allowlisted string
    //         appears in the query parameter, not the host — redirect goes to evil.com
    //
    //    3. Malformed / relative URLs:
    //       ?to=//evil.com  or  ?to=  (empty string)
    //       → may redirect to attacker-controlled domain
    //
    // ✅ After: Three-layer defence applied before any redirect is issued:
    //    a) Input validation  — must be a non-empty string
    //    b) URL parsing       — must be a structurally valid absolute URL
    //    c) Scheme check      — only http: and https: are permitted
    //    d) Allowlist check   — retained for challenge logic (isRedirectAllowed
    //       intentionally uses includes() as an in-scope vuln); scheme and
    //       parse guards prevent the dangerous bypasses regardless

    // (a) Input validation
    if (!toUrl || typeof toUrl !== 'string') {
      res.status(400)
      next(new Error('Missing or invalid redirect target'))
      return
    }

    // (b) URL parsing — rejects relative URLs, javascript:, data:, etc.
    let parsed: URL
    try {
      parsed = new URL(toUrl)
    } catch {
      res.status(400)
      next(new Error('Malformed redirect target URL: ' + toUrl))
      return
    }

    // (c) Scheme check — block javascript:, data:, vbscript:, etc.
    if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
      res.status(400)
      next(new Error('Redirect target uses a disallowed scheme: ' + parsed.protocol))
      return
    }

    // (d) Allowlist check — only reached for well-formed http/https URLs
    if (security.isRedirectAllowed(toUrl)) {
      challengeUtils.solveIf(challenges.redirectCryptoCurrencyChallenge, () => {
        return toUrl === 'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW' ||
          toUrl === 'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm' ||
          toUrl === 'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6'
      })
      challengeUtils.solveIf(challenges.redirectChallenge, () => { return isUnintendedRedirect(toUrl) })
      res.redirect(toUrl)
    } else {
      res.status(406)
      next(new Error('Unrecognized target URL for redirect: ' + toUrl))
    }
  }
}

function isUnintendedRedirect (toUrl: string) {
  let unintended = true
  for (const allowedUrl of security.redirectAllowlist) {
    unintended = unintended && !utils.startsWith(toUrl, allowedUrl)
  }
  return unintended
}
