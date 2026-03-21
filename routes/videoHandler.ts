/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import pug from 'pug'
import path from 'node:path'
import config from 'config'
import { type Request, type Response } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const entities = new Entities()

// ✅ FIX: Resolve the allowed video directory once at module load time to
// prevent path traversal in videoPath() and getSubsFromFile().
const VIDEOS_ROOT = path.resolve('frontend/dist/frontend/assets/public/videos')

export const getVideo = () => {
  return (req: Request, res: Response) => {
    const filePath = videoPath()
    const stat = fs.statSync(filePath)
    const fileSize = stat.size
    const range = req.headers.range
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-')
      const start = parseInt(parts[0], 10)
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1
      const chunksize = (end - start) + 1
      const file = fs.createReadStream(filePath, { start, end })
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Type': 'video/mp4'
      }
      res.writeHead(206, head)
      file.pipe(res)
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4'
      }
      res.writeHead(200, head)
      fs.createReadStream(filePath).pipe(res)
    }
  }
}

export const promotionVideo = () => {
  return (req: Request, res: Response) => {
    fs.readFile('views/promotionVideo.pug', function (err, buf) {
      if (err != null) throw err
      let template = buf.toString()
      const subs = getSubsFromFile()

      challengeUtils.solveIf(challenges.videoXssChallenge, () => { return utils.contains(subs, '</script><script>alert(`xss`)</script>') })

      const themeKey = config.get<string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      template = template.replace(/_title_/g, entities.encode(config.get<string>('application.name')))
      template = template.replace(/_favicon_/g, favicon())
      template = template.replace(/_bgColor_/g, theme.bgColor)
      template = template.replace(/_textColor_/g, theme.textColor)
      template = template.replace(/_navColor_/g, theme.navColor)
      template = template.replace(/_primLight_/g, theme.primLight)
      template = template.replace(/_primDark_/g, theme.primDark)
      const fn = pug.compile(template)
      let compiledTemplate = fn()

      // ✅ FIX: Sanitize subtitle content before injecting into a <script> tag.
      // ❌ Before: subs injected raw → '</script><script>alert(1)</script>' in a
      //    subtitle file immediately breaks out of the script block and executes
      //    arbitrary JavaScript (stored XSS). The videoXssChallenge intentionally
      //    demonstrates this exact bypass, but the sanitization must happen AFTER
      //    the challenge check so the challenge can still be solved.
      //
      // ✅ After: sanitizeSubtitleContent() removes or escapes sequences that
      //    would terminate the enclosing <script> block:
      //    - '</script'  (case-insensitive) — the primary escape vector
      //    - '<!--'      — HTML comment opener that some parsers treat specially
      //    The subtitle format (WebVTT) does not use these sequences legitimately,
      //    so removing them does not affect correct subtitle rendering.
      //
      // Note: the videoXssChallenge check above intentionally looks for the raw
      // malicious string *before* sanitization so the challenge is still solvable
      // by uploading a crafted VTT file — the check fires on the unsanitized value.
      // Only the output to the browser is sanitized.
      const safeSubs = sanitizeSubtitleContent(subs)
      compiledTemplate = compiledTemplate.replace(
        '<script id="subtitle"></script>',
        '<script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + safeSubs + '</script>'
      )
      res.send(compiledTemplate)
    })
  }

  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}

// ✅ FIX: Strip sequences that can break out of a <script> block.
// WebVTT files are plain-text subtitle format and never legitimately contain
// </script or <!-- so these replacements are safe for real subtitle content.
function sanitizeSubtitleContent (content: string): string {
  return content
    .replace(/<\/script/gi, '<\\/script') // escape closing script tag
    .replace(/<!--/g, '<\\!--')           // escape HTML comment opener
}

function getSubsFromFile () {
  const subtitles = config.get<string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'

  // ✅ FIX: Directory jail for subtitle file path.
  // ❌ Before: path built by string concatenation with no traversal check —
  //    a config value of '../../etc/passwd' would read an arbitrary file.
  const safeFilename = utils.extractFilename(subtitles)
  const resolvedPath = path.resolve(VIDEOS_ROOT, safeFilename)
  if (!resolvedPath.startsWith(VIDEOS_ROOT + path.sep) && resolvedPath !== VIDEOS_ROOT) {
    throw new Error('Path traversal detected in subtitle filename')
  }

  const data = fs.readFileSync(resolvedPath, 'utf8')
  return data.toString()
}

function videoPath () {
  if (config.get<string>('application.promotion.video') !== null) {
    const video = utils.extractFilename(config.get<string>('application.promotion.video'))

    // ✅ FIX: Directory jail for video file path.
    const resolvedPath = path.resolve(VIDEOS_ROOT, video)
    if (!resolvedPath.startsWith(VIDEOS_ROOT + path.sep) && resolvedPath !== VIDEOS_ROOT) {
      throw new Error('Path traversal detected in video filename')
    }
    return resolvedPath
  }
  return path.join(VIDEOS_ROOT, 'owasp_promo.mp4')
}
