// Server-side syntax highlighting for the code samples (views/fragments/code-samples.ejs).
// Only the languages the samples use are registered, to keep startup light.
import hljs from 'highlight.js/lib/core';
import javascript from 'highlight.js/lib/languages/javascript';
import typescript from 'highlight.js/lib/languages/typescript';
import python from 'highlight.js/lib/languages/python';
import csharp from 'highlight.js/lib/languages/csharp';
import java from 'highlight.js/lib/languages/java';
import xml from 'highlight.js/lib/languages/xml';
import json from 'highlight.js/lib/languages/json';
import yaml from 'highlight.js/lib/languages/yaml';
import bash from 'highlight.js/lib/languages/bash';

for (const [name, lang] of Object.entries({ javascript, typescript, python, csharp, java, xml, json, yaml, bash })) {
  hljs.registerLanguage(name, lang);
}

const escapeHtml = (s) => s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

// Returns HTML-safe markup for `code`; unknown languages come back escaped but unhighlighted.
export function highlight(code, language) {
  if (!language || !hljs.getLanguage(language)) return escapeHtml(code);
  return hljs.highlight(code, { language, ignoreIllegals: true }).value;
}
