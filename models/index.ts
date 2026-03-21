/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */
import { AddressModelInit } from './address'
import { BasketModelInit } from './basket'
import { BasketItemModelInit } from './basketitem'
import { CaptchaModelInit } from './captcha'
import { CardModelInit } from './card'
import { ChallengeModelInit } from './challenge'
import { ComplaintModelInit } from './complaint'
import { DeliveryModelInit } from './delivery'
import { FeedbackModelInit } from './feedback'
import { HintModelInit } from './hint'
import { ImageCaptchaModelInit } from './imageCaptcha'
import { MemoryModelInit } from './memory'
import { PrivacyRequestModelInit } from './privacyRequests'
import { ProductModelInit } from './product'
import { QuantityModelInit } from './quantity'
import { RecycleModelInit } from './recycle'
import { relationsInit } from './relations'
import { SecurityAnswerModelInit } from './securityAnswer'
import { SecurityQuestionModelInit } from './securityQuestion'
import { UserModelInit } from './user'
import { WalletModelInit } from './wallet'
import { Sequelize, Transaction } from 'sequelize'

// ✅ FIX: Load database credentials from environment variables.
// ❌ Before: new Sequelize('database', 'username', 'password', ...)
//    Hardcoded credential strings committed to source control are exposed to
//    anyone with repo read access — including CI logs, forks, and git history.
//    Even though SQLite ignores username/password for local file access, these
//    strings signal a pattern that is dangerous if copy-pasted to a real DB
//    (PostgreSQL, MySQL, etc.) and will be flagged by secret scanners in CI.
// ✅ After: credentials come from environment variables with safe fallbacks
//    for the SQLite development case where auth is not enforced.
//
// Required env vars for production (non-SQLite) deployments:
//   DB_NAME      — database name          (default: 'juiceshop')
//   DB_USERNAME  — database user          (default: '')
//   DB_PASSWORD  — database password      (default: '')
//   DB_STORAGE   — path to SQLite file    (default: 'data/juiceshop.sqlite')

/* jslint node: true */
const sequelize = new Sequelize(
  process.env.DB_NAME ?? 'juiceshop',
  process.env.DB_USERNAME ?? '',
  process.env.DB_PASSWORD ?? '',
  {
    dialect: 'sqlite',
    retry: {
      match: [/SQLITE_BUSY/],
      name: 'query',
      max: 5
    },
    transactionType: Transaction.TYPES.IMMEDIATE,
    storage: process.env.DB_STORAGE ?? 'data/juiceshop.sqlite',
    logging: false
  }
)

AddressModelInit(sequelize)
BasketModelInit(sequelize)
BasketItemModelInit(sequelize)
CaptchaModelInit(sequelize)
CardModelInit(sequelize)
ChallengeModelInit(sequelize)
ComplaintModelInit(sequelize)
DeliveryModelInit(sequelize)
FeedbackModelInit(sequelize)
HintModelInit(sequelize)
ImageCaptchaModelInit(sequelize)
MemoryModelInit(sequelize)
PrivacyRequestModelInit(sequelize)
ProductModelInit(sequelize)
QuantityModelInit(sequelize)
RecycleModelInit(sequelize)
SecurityAnswerModelInit(sequelize)
SecurityQuestionModelInit(sequelize)
UserModelInit(sequelize)
WalletModelInit(sequelize)
relationsInit(sequelize)

export { sequelize }
