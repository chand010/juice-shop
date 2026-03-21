/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import jwtDecode from 'jwt-decode'

let config: any
const playbackDelays: Record<string, number> = {
  faster: 0.5,
  fast: 0.75,
  normal: 1.0,
  slow: 1.25,
  slower: 1.5
}

// ✅ FIX: Safe property-chain traversal that blocks prototype pollution.
//
// ❌ Before (inline inside waitForInputToHaveValue):
//   const propertyChain = options.replacement[1].split('.')
//   let replacementValue = config
//   for (const property of propertyChain) {
//     replacementValue = replacementValue[property]   // ← bracket notation with user input
//   }
//
//   If options.replacement[1] is "__proto__.polluted" or "constructor.prototype.x",
//   the loop walks directly onto Object.prototype, allowing an attacker who controls
//   the tutorial JSON to inject properties onto every object in the application
//   (prototype pollution). This can bypass security checks, corrupt state, or
//   enable further exploitation depending on how polluted properties are consumed.
//
// ✅ After: safeGet() validates each segment before accessing it:
//   1. BLOCKED_KEYS rejects known prototype-access keys outright.
//   2. Object.prototype.hasOwnProperty.call() ensures we only traverse own
//      properties, never inherited prototype members.
//   3. Returns undefined on any violation rather than throwing, so callers
//      degrade gracefully.
const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype'])

function safeGet (obj: any, propertyChain: string[]): any {
  let current = obj
  for (const key of propertyChain) {
    if (BLOCKED_KEYS.has(key)) {
      console.warn(`Prototype pollution attempt blocked: property key "${key}" is not allowed`)
      return undefined
    }
    if (current === null || current === undefined || !Object.prototype.hasOwnProperty.call(current, key)) {
      return undefined
    }
    current = current[key]
  }
  return current
}

export async function isChallengeSolved (challengeName: string): Promise<boolean> {
  try {
    const res = await fetch('/api/Challenges/')
    const json = await res.json()
    const challenges: { name: string, solved: boolean }[] = json.data || []
    return challenges.some(c => c.name === challengeName && c.solved)
  } catch {
    return false
  }
}

export async function sleep (timeInMs: number): Promise<void> {
  await new Promise((resolve) => {
    setTimeout(resolve, timeInMs)
  })
}

export function waitForInputToHaveValue (inputSelector: string, value: string, options: any = { ignoreCase: true, replacement: [] }) {
  return async () => {
    const inputElement: HTMLInputElement = document.querySelector(
      inputSelector
    )

    if (options.replacement?.length === 2) {
      if (!config) {
        const res = await fetch('/rest/admin/application-configuration')
        const json = await res.json()
        config = json.config
      }

      // ✅ FIX: Use safeGet() with explicit BLOCKED_KEYS check instead of
      //    bare bracket-notation traversal over a user-supplied property path.
      const propertyChain = String(options.replacement[1]).split('.')
      const replacementValue = safeGet(config, propertyChain)
      if (replacementValue !== undefined) {
        value = value.replace(options.replacement[0], replacementValue)
      }
    }

    while (true) {
      if (options.ignoreCase && inputElement.value.toLowerCase() === value.toLowerCase()) {
        break
      } else if (!options.ignoreCase && inputElement.value === value) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForInputToNotHaveValue (inputSelector: string, value: string, options = { ignoreCase: true }) {
  return async () => {
    const inputElement: HTMLInputElement = document.querySelector(
      inputSelector
    )

    while (true) {
      if (options.ignoreCase && inputElement.value.toLowerCase() !== value.toLowerCase()) {
        break
      } else if (!options.ignoreCase && inputElement.value !== value) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForInputToNotHaveValueAndNotBeEmpty (inputSelector: string, value: string, options = { ignoreCase: true }) {
  return async () => {
    const inputElement: HTMLInputElement = document.querySelector(
      inputSelector
    )

    while (true) {
      if (inputElement.value !== '') {
        if (options.ignoreCase && inputElement.value.toLowerCase() !== value.toLowerCase()) {
          break
        } else if (!options.ignoreCase && inputElement.value !== value) {
          break
        }
      }
      await sleep(100)
    }
  }
}

export function waitForInputToNotBeEmpty (inputSelector: string) {
  return async () => {
    const inputElement: HTMLInputElement = document.querySelector(
      inputSelector
    )

    while (true) {
      if (inputElement.value && inputElement.value !== '') {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForElementToGetClicked (elementSelector: string) {
  return async () => {
    const element = document.querySelector(
      elementSelector
    )
    if (!element) {
      console.warn(`Could not find Element with selector "${elementSelector}"`)
    }

    await new Promise<void>((resolve) => {
      element.addEventListener('click', () => { resolve() })
    })
  }
}

export function waitForElementsInnerHtmlToBe (elementSelector: string, value: string) {
  return async () => {
    while (true) {
      const element = document.querySelector(
        elementSelector
      )

      if (element && element.innerHTML === value) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitInMs (timeInMs: number) {
  return async () => {
    if (!config) {
      const res = await fetch('/rest/admin/application-configuration')
      const json = await res.json()
      config = json.config
    }
    let delay = playbackDelays[config.hackingInstructor.hintPlaybackSpeed]
    delay ??= 1.0
    await sleep(timeInMs * delay)
  }
}

export function waitForAngularRouteToBeVisited (route: string) {
  return async () => {
    while (true) {
      if (window.location.hash.startsWith(`#/${route}`)) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForLogIn () {
  return async () => {
    while (true) {
      if (localStorage.getItem('token') !== null) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForAdminLogIn () {
  return async () => {
    while (true) {
      let role = ''
      try {
        const token: string = localStorage.getItem('token')
        const decodedToken = jwtDecode(token)
        const payload = decodedToken as any
        role = payload.data.role
      } catch {
        console.log('Role from token could not be accessed.')
      }
      if (role === 'admin') {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForLogOut () {
  return async () => {
    while (true) {
      if (localStorage.getItem('token') === null) {
        break
      }
      await sleep(100)
    }
  }
}

/**
 * see https://stackoverflow.com/questions/7798748/find-out-whether-chrome-console-is-open/48287643#48287643
 * does detect when devtools are opened horizontally or vertically but not when undocked or open on page load
 */
export function waitForDevTools () {
  const initialInnerHeight = window.innerHeight
  const initialInnerWidth = window.innerWidth
  return async () => {
    while (true) {
      if (window.innerHeight !== initialInnerHeight || window.innerWidth !== initialInnerWidth) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForSelectToHaveValue (selectSelector: string, value: string) {
  return async () => {
    const selectElement: HTMLSelectElement = document.querySelector(
      selectSelector
    )

    while (true) {
      if (selectElement.options[selectElement.selectedIndex].value === value) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForSelectToNotHaveValue (selectSelector: string, value: string) {
  return async () => {
    const selectElement: HTMLSelectElement = document.querySelector(
      selectSelector
    )

    while (true) {
      if (selectElement.options[selectElement.selectedIndex].value !== value) {
        break
      }
      await sleep(100)
    }
  }
}

export function waitForRightUriQueryParamPair (key: string, value: string) {
  return async () => {
    while (true) {
      const encodedValue: string = encodeURIComponent(value).replace(/%3A/g, ':')
      const encodedKey: string = encodeURIComponent(key).replace(/%3A/g, ':')
      const expectedHash = `#/track-result/new?${encodedKey}=${encodedValue}`

      if (window.location.hash === expectedHash) {
        break
      }
      await sleep(100)
    }
  }
}
