import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'

import { expect, test } from 'vitest'

const manifest = JSON.parse(readFileSync(resolve('package.json'), 'utf8')) as {
	peerDependencies: Record<string, string>
	devDependencies: Record<string, string>
}

const numeric = { numeric: true }

test('declares the design system window this build is tested against', () => {
	expect(manifest.peerDependencies['@wordpress/ui']).toBe('>=0.23.0 <0.24.0')
	expect(manifest.peerDependencies['@wordpress/theme']).toBe('>=2.2.0 <3.0.0')
	expect(manifest.peerDependencies['@wordpress/i18n']).toBe('>=6.29.0 <7.0.0')
})

test.each(['@wordpress/i18n', '@wordpress/theme', '@wordpress/ui'])('pins %s inside its peer window', (name) => {
	const range = /^>=(\S+) <(\S+)$/.exec(manifest.peerDependencies[name])
	const pin = manifest.devDependencies[name]

	expect(range, `${name} has no longhand peer range`).not.toBeNull()
	expect(pin, `${name} is not pinned exactly`).toMatch(/^\d+\.\d+\.\d+$/)
	expect(pin.localeCompare(range?.[1] ?? '', 'en', numeric), `${pin} is below ${range?.[1]}`).toBeGreaterThanOrEqual(0)
	expect(pin.localeCompare(range?.[2] ?? '', 'en', numeric), `${pin} reaches ${range?.[2]}`).toBeLessThan(0)
})
