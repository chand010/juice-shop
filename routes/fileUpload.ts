/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import os from 'node:os'
import fs from 'node:fs'
import path from 'node:path'
import yaml from 'js-yaml'
import unzipper from 'unzipper'
import { DOMParser } from '@xmldom/xmldom'
import { type NextFunction, type Request, type Response } from 'express'

// ✅ Removed: import vm from 'node:vm'       — no code execution needed
// ✅ Removed: import libxml from 'libxmljs2' — XXE-prone, replaced with @xmldom/xmldom

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

export function ensureFileIsPassed ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    next()
  } else {
    return res.status(400).json({ error: 'File is not passed' })
  }
}

export function handleZipFileUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.zip')) {
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.fileWriteChallenge)) {
      const buffer = file.buffer

      // ✅ FIX PATH TRAVERSAL (temp file): sanitize originalname before
      //    using it in path.join() for the temp file.
      //
      // ❌ Before:
      //   const filename = file.originalname.toLowerCase()
      //   const tempFile = path.join(os.tmpdir(), filename)
      //
      //   path.join() does NOT normalise '../' sequences — it only joins
      //   segments. A filename like '../../etc/cron.d/evil.zip' would resolve
      //   to a path outside os.tmpdir(), allowing an attacker to write an
      //   arbitrary file anywhere the process has write permission.
      //
      //   Example:
      //     os.tmpdir()  = '/tmp'
      //     filename     = '../../etc/cron.d/evil.zip'
      //     path.join()  = '/etc/cron.d/evil.zip'   ← OUTSIDE tmpdir!
      //
      // ✅ After: path.basename() strips all directory components, keeping
      //   only the final filename segment. Combined with a directory-jail
      //   check on the resolved path, the temp file is always inside tmpdir.
      const safeName = path.basename(file.originalname.toLowerCase())
      const tmpDir = os.tmpdir()
      const tempFile = path.resolve(tmpDir, safeName)

      // Jail check: confirm resolved path stays inside tmpdir
      if (!tempFile.startsWith(tmpDir + path.sep)) {
        next(new Error('Blocked illegal temp file path'))
        return
      }

      fs.open(tempFile, 'w', function (err, fd) {
        if (err != null) { next(err) }
        fs.write(fd, buffer, 0, buffer.length, null, function (err) {
          if (err != null) { next(err) }
          fs.close(fd, function () {
            fs.createReadStream(tempFile)
              .pipe(unzipper.Parse())
              .on('entry', function (entry: any) {
                const entryFileName = entry.path

                // ✅ FIX PATH TRAVERSAL (zip entry): basename + directory jail
                const safeEntryName = path.basename(entryFileName)
                const allowedDir = path.resolve('uploads/complaints')
                const absolutePath = path.resolve(allowedDir, safeEntryName)

                challengeUtils.solveIf(challenges.fileWriteChallenge, () => {
                  return absolutePath === path.resolve('ftp/legal.md')
                })

                if (absolutePath.startsWith(allowedDir + path.sep)) {
                  entry.pipe(fs.createWriteStream(absolutePath).on('error', function (err) { next(err) }))
                } else {
                  entry.autodrain()
                }
              }).on('error', function (err: unknown) { next(err) })
          })
        })
      })
    }
    res.status(204).end()
  } else {
    next()
  }
}

export function checkUploadSize ({ file }: Request, res: Response, next: NextFunction) {
  if (file != null) {
    challengeUtils.solveIf(challenges.uploadSizeChallenge, () => { return file?.size > 100000 })
  }
  next()
}

export function checkFileType ({ file }: Request, res: Response, next: NextFunction) {
  const fileType = file?.originalname.substr(file.originalname.lastIndexOf('.') + 1).toLowerCase()
  challengeUtils.solveIf(challenges.uploadTypeChallenge, () => {
    return !(fileType === 'pdf' || fileType === 'xml' || fileType === 'zip' || fileType === 'yml' || fileType === 'yaml')
  })
  next()
}

export function handleXmlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.xml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      try {
        // ✅ FIX XXE: @xmldom/xmldom never processes external entities
        // ✅ FIX vm:  removed vm.createContext/runInContext entirely
        const parser = new DOMParser()
        const xmlDoc = parser.parseFromString(data, 'text/xml')
        const xmlString = xmlDoc.toString()

        challengeUtils.solveIf(challenges.xxeFileDisclosureChallenge, () => {
          return (utils.matchesEtcPasswdFile(xmlString) || utils.matchesSystemIniFile(xmlString))
        })
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(xmlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  next()
}

export function handleYamlUpload ({ file }: Request, res: Response, next: NextFunction) {
  if (utils.endsWith(file?.originalname.toLowerCase(), '.yml') || utils.endsWith(file?.originalname.toLowerCase(), '.yaml')) {
    challengeUtils.solveIf(challenges.deprecatedInterfaceChallenge, () => { return true })
    if (((file?.buffer) != null) && utils.isChallengeEnabled(challenges.deprecatedInterfaceChallenge)) {
      const data = file.buffer.toString()
      try {
        // ✅ FIX YAML RCE: FAILSAFE_SCHEMA blocks !!js/function execution
        // ✅ FIX vm:        removed vm.createContext/runInContext entirely
        const parsed = yaml.load(data, { schema: yaml.FAILSAFE_SCHEMA })
        const yamlString = JSON.stringify(parsed)

        res.status(410)
        next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + utils.trunc(yamlString, 400) + ' (' + file.originalname + ')'))
      } catch (err: unknown) {
        const errorMessage = err instanceof Error ? err.message : String(err)
        if (utils.contains(errorMessage, 'Invalid string length')) {
          if (challengeUtils.notSolved(challenges.yamlBombChallenge)) {
            challengeUtils.solve(challenges.yamlBombChallenge)
          }
          res.status(503)
          next(new Error('Sorry, we are temporarily not available! Please try again later.'))
        } else {
          res.status(410)
          next(new Error('B2B customer complaints via file upload have been deprecated for security reasons: ' + errorMessage + ' (' + file.originalname + ')'))
        }
      }
    } else {
      res.status(410)
      next(new Error('B2B customer complaints via file upload have been deprecated for security reasons (' + file?.originalname + ')'))
    }
  }
  res.status(204).end()
}
