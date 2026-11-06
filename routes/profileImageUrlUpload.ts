/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { lookup } from 'node:dns/promises'
import http from 'node:http'
import https from 'node:https'
import { isIP } from 'node:net'
import { type IncomingMessage } from 'node:http'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

function publicAddress (address: string): boolean {
  if (address.includes(':')) return false
  const octets = address.split('.').map(Number)
  return octets.length === 4 && octets[0] !== 0 && octets[0] !== 10 && octets[0] !== 127 && octets[0] < 224 &&
    !(octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) &&
    !(octets[0] === 169 && octets[1] === 254) &&
    !(octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) &&
    !(octets[0] === 192 && (octets[1] === 168 || (octets[1] === 0 && octets[2] === 0))) &&
    !(octets[0] === 198 && (octets[1] === 18 || octets[1] === 19))
}

async function allowedImageUrl (input: unknown): Promise<{ url: URL, address: string } | null> {
  if (typeof input !== 'string') return null
  let url: URL
  try { url = new URL(input) } catch { return null }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password ||
      (url.port && url.port !== (url.protocol === 'https:' ? '443' : '80'))) return null
  if (isIP(url.hostname)) return publicAddress(url.hostname) ? { url, address: url.hostname } : null
  try {
    const addresses = await lookup(url.hostname, { all: true })
    const ipv4 = addresses.filter(({ family }) => family === 4)
    return ipv4.length > 0 && ipv4.every(({ address }) => publicAddress(address))
      ? { url, address: ipv4[0].address }
      : null
  } catch { return null }
}

async function fetchImage (url: URL, address: string): Promise<IncomingMessage> {
  return await new Promise((resolve, reject) => {
    const client = url.protocol === 'https:' ? https : http
    const request = client.get(url, {
      lookup: (_hostname, _options, callback) => callback(null, address, 4),
      timeout: 15000
    }, resolve)
    request.on('timeout', () => request.destroy(new Error('Image request timed out')))
    request.on('error', reject)
  })
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const target = await allowedImageUrl(url)
        if (!target) {
          res.status(400).send('Profile image URL must point to a public HTTP or HTTPS address')
          return
        }
        try {
          const response = await fetchImage(target.url, target.address)
          if ((response.statusCode ?? 500) < 200 || (response.statusCode ?? 500) >= 300) {
            response.resume()
            throw new Error('url returned a non-OK status code')
          }
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          await finished(response.pipe(fileStream))
          const user = await UserModel.findByPk(loggedInUser.data.id)
          await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` })
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
