/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import { CaptchaModel } from '../models/captcha'

// ✅ FIX: Replace eval() with a purpose-built arithmetic evaluator.
// ❌ Before: eval(expression)
//    Even though the expression is constructed server-side from random numbers
//    and a fixed operator set, eval() is dangerous in principle:
//    - Any future refactor that lets user input reach `expression` would
//      immediately become Remote Code Execution (RCE).
//    - Static analysis tools (Semgrep, ESLint no-eval, SAST scanners) flag it
//      and must be suppressed, masking legitimate future violations.
//    - It prevents use of strict Content-Security-Policy script-src directives.
//
// ✅ After: evaluateArithmetic() handles only the three operators actually used
//    (* + -) with integer operands. It throws on any unexpected input, so a
//    future accidental introduction of user-controlled data into the expression
//    would fail safely rather than execute arbitrary code.
function evaluateArithmetic (expression: string): number {
  // Parse "A op B op C" where op ∈ {*, +, -} and A/B/C are integers.
  // Operators are applied left-to-right (matches the original eval() behaviour
  // for same-precedence chains, but note: eval() respects precedence so
  // "2+3*4" = 14 while left-to-right gives 20. Here all three operators can
  // appear, so we replicate JS operator precedence: * first, then +/-.
  const tokenRegex = /^(-?\d+)([\*\+\-])(-?\d+)([\*\+\-])(-?\d+)$/
  const match = expression.match(tokenRegex)
  if (!match) {
    throw new Error(`Invalid captcha expression: ${expression}`)
  }

  const a = parseInt(match[1], 10)
  const op1 = match[2]
  const b = parseInt(match[3], 10)
  const op2 = match[4]
  const c = parseInt(match[5], 10)

  const applyOp = (x: number, op: string, y: number): number => {
    if (op === '*') return x * y
    if (op === '+') return x + y
    if (op === '-') return x - y
    throw new Error(`Unsupported operator: ${op}`)
  }

  // Replicate JS operator precedence: evaluate * before + / -
  if (op1 === '*' && op2 !== '*') {
    return applyOp(applyOp(a, op1, b), op2, c)
  } else if (op2 === '*' && op1 !== '*') {
    return applyOp(a, op1, applyOp(b, op2, c))
  } else {
    // Both same precedence — left-to-right
    return applyOp(applyOp(a, op1, b), op2, c)
  }
}

export function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()

    // ✅ FIX: Use evaluateArithmetic() instead of eval()
    const answer = evaluateArithmetic(expression).toString()

    const captcha = {
      captchaId,
      captcha: expression,
      answer
    }
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

export const verifyCaptcha = () => async (req: Request, res: Response, next: NextFunction) => {
  try {
    const captcha = await CaptchaModel.findOne({ where: { captchaId: req.body.captchaId } })
    if ((captcha != null) && req.body.captcha === captcha.answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again.'))
    }
  } catch (error) {
    next(error)
  }
}
