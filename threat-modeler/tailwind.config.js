/** Vendored Tailwind build for ThreatGuard.
 *
 *  The app used to load the Tailwind Play CDN (cdn.tailwindcss.com) at runtime,
 *  which Tailwind documents as unsuitable for production and which makes the
 *  entire UI depend on a third-party host being reachable from every visitor's
 *  browser — so on an offline / air-gapped / CDN-blocked network the whole UI
 *  rendered unstyled. This config compiles the used utilities into a static
 *  stylesheet (static/css/tailwind.css) so the UI needs no external CDN.
 *
 *  Rebuild:  ./scripts/build_css.sh
 */
module.exports = {
  content: [
    "./templates/**/*.html",
    "./static/js/**/*.js",
  ],
  theme: {
    extend: {
      colors: {
        // Canonical brand = the indigo palette the main app (_base.html) used.
        brand: {
          50: '#eef2ff', 100: '#e0e7ff', 200: '#c7d2fe', 300: '#a5b4fc',
          400: '#818cf8', 500: '#6366f1', 600: '#4f46e5', 700: '#4338ca',
          800: '#3730a3', 900: '#312e81',
        },
        slate: { 950: '#020617' },
      },
    },
  },
};
