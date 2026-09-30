# Golden Pace: Daily Vitality & Wellness Tracker

A mobile-first web app for older adults to log blood pressure, weight, exercise, hydration and
meals, follow guided tai chi / bike / dumbbell routines, and take simple balance and chair-stand
tests. Data stays on the device (IndexedDB). Export a CSV for a doctor visit or a JSON backup from
the Vault menu.

Golden Pace is a personal logging tool, not medical advice.

## Profiles and PIN lock
Several people can share one device. Each person adds a profile (name, picture, optional 4 to 6 digit PIN)
and gets a completely separate database, so records never mix. PINs are stored only as salted PBKDF2
hashes, wrong guesses are slowed down, and PIN-protected profiles lock after 5 minutes away. The PIN is a
privacy screen, not encryption (the Privacy Policy says so). Records saved before profiles existed become
the first profile ("My Profile") automatically. There are no online accounts: nothing leaves the device.

## Pages
`privacy.html`, `terms.html` and `faq.html` are linked from the app and work offline. The contact point in
them is this repository's Issues page; replace it with your own email or website, and have the legal pages
reviewed by a qualified attorney before submitting to an app store.

## Works offline
Styles are compiled at build time and the libraries are bundled in `vendor/`, so nothing loads from
the internet. A service worker caches the app so it opens without a connection, and it can be
installed to a phone's home screen (Share, then "Add to Home Screen").

## Run it
Serve the repo root with any static web server, for example `python3 -m http.server 8123`, and open
`http://localhost:8123`. Offline mode and install need `http(s)`; opening `index.html` directly as a
file still works but without the service worker.

Deploys as a plain static site (for example on Railway or Netlify). There is intentionally no
`package.json` at the root, so hosts treat it as static files.

## Rebuild styles and libraries
Only needed after editing classes in `index.html` or updating a library:

    cd tools
    npm install
    npm run build

This regenerates `styles.css`, refreshes `vendor/`, and stamps `sw.js` with a new cache version so
installed copies update. Library versions are pinned in `tools/package.json`.

## Meal analysis (optional)
Add a Google Gemini API key under Settings. It is stored only in the browser's local storage and is
never part of this repository.

## Third-party libraries (all MIT licensed)
Tailwind CSS (build only), Chart.js, Dexie.js, canvas-confetti.
