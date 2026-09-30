/** Tailwind config (extracted from the old in-page CDN config). */
module.exports = Object.assign({
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            brand: {
              50: '#f2f8f4',
              100: '#e1efe6',
              200: '#c5dfd1',
              300: '#8fc3a7',
              400: '#5fa383',
              500: '#347a57',
              600: '#286244',
              700: '#1e4b34',
              800: '#163827',
              900: '#0e2419',
            },
            amberlead: {
              50: '#fefbf3',
              100: '#faecc8',
              400: '#fbbf24',
              500: '#f59e0b',
              600: '#d97706',
              700: '#b45309',
            },
            warmgray: {
              50: '#fcfbfa',
              100: '#f4f0ea',
              200: '#e7e2d7',
              300: '#d5cec0',
              400: '#8a8474',
              500: '#6b6556',
              600: '#524e43',
              700: '#48443b',
              800: '#322f28',
              900: '#1c1a16'
            }
          },
          fontFamily: {
            sans: ['-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica', 'Arial', 'sans-serif']
          }
        }
      }
    }, {
  content: ['../index.html', '../privacy.html', '../terms.html', '../faq.html','../welcome.html']
});
