import path from 'node:path'
import { promises as fs } from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

const FTP_ROOT = path.resolve('ftp')
const ALLOWED_EXTENSIONS = new Set(['.md', '.pdf'])
const ALLOWED_EXACT_NAMES = new Set(['incident-support.kdbx'])

export function servePublicFiles () {
  return async ({ params }: Request, res: Response, next: NextFunction) => {
    try {
      const file = params.file

      // 1. Reject anything suspicious up front: wrong type, empty, null bytes, separators
      if (
        typeof file !== 'string' ||
        file.length === 0 ||
        file.includes('\0') ||
        file.includes('/') ||
        file.includes('\\')
      ) {
        res.status(403)
        return next(new Error('Invalid file name!'))
      }

      // 2. Canonicalize, then validate the SAME value that will be used
      const safeFilename = path.basename(file)
      const ext = path.extname(safeFilename).toLowerCase()

      if (!ALLOWED_EXTENSIONS.has(ext) && !ALLOWED_EXACT_NAMES.has(safeFilename)) {
        res.status(403)
        return next(new Error('Only .md and .pdf files are allowed!'))
      }

      // 3. Containment check: the resolved path must stay inside the ftp directory
      const resolved = path.resolve(FTP_ROOT, safeFilename)
      if (!resolved.startsWith(FTP_ROOT + path.sep)) {
        res.status(403)
        return next(new Error('Access denied!'))
      }

      // 4. Look the name up in the real directory listing and serve the trusted entry,
      //    not the request value. This also breaks the taint flow for Semgrep.
      const entries = await fs.readdir(FTP_ROOT, { withFileTypes: true })
      const match = entries.find((entry) => entry.isFile() && entry.name === safeFilename)

      if (!match) {
        res.status(404)
        return next(new Error('File not found'))
      }

      res.sendFile(match.name, { root: FTP_ROOT, dotfiles: 'deny' }, (err) => {
        if (err) next(err)
      })
    } catch (err) {
      next(err)
    }
  }
}
