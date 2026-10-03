import { Marked } from 'marked';
import { highlight } from './highlight.js';

// Renders the portal's own Markdown documents (e.g. the API agent guide) as HTML for its pages:
// headings get ids for anchors and a table of contents, code blocks the site's code-window style.
// Only for Markdown the portal writes itself: it is not sanitized.

const LANGUAGES = { sh: 'bash', shell: 'bash', js: 'javascript', ts: 'typescript', py: 'python' };
const slug = (text) => text.toLowerCase().replace(/<[^>]+>/g, '').replace(/&[a-z#0-9]+;/g, '').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

// Returns { html, headings: [{ id, text, depth }] }.
export function renderMarkdown(markdown, { shiftHeadings = 0 } = {}) {
  const headings = [];
  const marked = new Marked({
    gfm: true,
    renderer: {
      heading({ tokens, depth }) {
        const text = this.parser.parseInline(tokens);
        const level = Math.min(depth + shiftHeadings, 6);
        let id = slug(text);
        while (headings.some((h) => h.id === id)) id += '-';
        headings.push({ id, text: text.replace(/<[^>]+>/g, ''), depth });
        return `<h${level} id="${id}"><a href="#${id}">${text}</a></h${level}>\n`;
      },
      code({ text, lang }) {
        const language = LANGUAGES[lang] ?? lang;
        return `<pre class="code-window overflow-x-auto rounded-lg border border-zinc-800 bg-zinc-950 p-4 text-xs text-zinc-100"><code class="hljs">${highlight(text, language)}</code></pre>\n`;
      },
    },
  });
  return { html: marked.parse(markdown), headings };
}
