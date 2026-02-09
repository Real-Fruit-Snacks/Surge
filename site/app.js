// Global error handler for restrictive environments (CSP, blocked scripts)
window.addEventListener('error', (e) => {
  console.error('SURGE: Global Error:', e.message, 'at', e.filename, ':', e.lineno);
  // Check for CSP violations
  if (e.message.includes('Content Security Policy')) {
    console.warn('SURGE: CSP Violation detected. Inline scripts or styles might be blocked.');
  }
});

window.addEventListener('unhandledrejection', (e) => {
  console.error('SURGE: Unhandled Promise Rejection:', e.reason);
});

// Safe localStorage wrapper for restricted environments
const safeStorage = {
  getItem(key) {
    try {
      return localStorage.getItem(key);
    } catch (e) {
      console.warn('localStorage not available:', e.message);
      return null;
    }
  },
  setItem(key, value) {
    try {
      localStorage.setItem(key, value);
    } catch (e) {
      console.warn('localStorage not available:', e.message);
    }
  },
  removeItem(key) {
    try {
      localStorage.removeItem(key);
    } catch (e) {
      console.warn('localStorage not available:', e.message);
    }
  }
};

// Safe highlight.js wrapper for restricted environments (CSP, blocked scripts)
// Configure highlight.js to ignore <Variable> syntax (not actual HTML)
if (typeof hljs !== 'undefined') {
  hljs.configure({ ignoreUnescapedHTML: true });
}

const safeHljs = {
  available: typeof hljs !== 'undefined',
  highlight(code, options) {
    if (!this.available) return { value: this.escapeHtml(code) };
    try {
      return hljs.highlight(code, options);
    } catch (e) {
      return { value: this.escapeHtml(code) };
    }
  },
  highlightAuto(code) {
    if (!this.available) return { value: this.escapeHtml(code) };
    try {
      return hljs.highlightAuto(code);
    } catch (e) {
      return { value: this.escapeHtml(code) };
    }
  },
  highlightElement(el) {
    if (!this.available) return;
    try {
      hljs.highlightElement(el);
    } catch (e) {
      console.warn('Syntax highlighting unavailable:', e.message);
    }
  },
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
};

    // Theme cycling
    const themes = ['mocha', 'macchiato', 'frappe', 'latte'];
    const themeNames = {
      mocha: 'Catppuccin Mocha', macchiato: 'Catppuccin Macchiato',
      frappe: 'Catppuccin Frappé', latte: 'Catppuccin Latte'
    };
    let currentTheme = safeStorage.getItem('theme') || 'mocha';

    function setTheme(theme) {
      themes.forEach(t => document.body.classList.remove('theme-' + t));
      if (theme !== 'mocha') {
        document.body.classList.add('theme-' + theme);
      }
      safeStorage.setItem('theme', theme);
      currentTheme = theme;
      document.getElementById('title').title = `Click to change theme · ${themeNames[theme]}`;
    }

    function toggleTheme() {
      const nextIndex = (themes.indexOf(currentTheme) + 1) % themes.length;
      setTheme(themes[nextIndex]);
    }

    // Load saved theme
    setTheme(currentTheme);

    // Code wrap toggle (default: wrapped)
    let wrapCode = safeStorage.getItem('wrapCode') !== 'false';

    function setWrap(wrap) {
      document.body.classList.toggle('wrap-code', wrap);
      safeStorage.setItem('wrapCode', wrap);
      wrapCode = wrap;
    }

    function toggleWrap() {
      setWrap(!wrapCode);
    }

    // Load saved wrap preference
    setWrap(wrapCode);

    // ===========================================
    // FILTER CONFIGURATION
    // Edit this array to customize which tags become filters.
    // - tag: The tag name in your notes (case-sensitive)
    // - label: Display name shown in the Filters dropdown
    // - default: true = show by default, false = hide by default
    // ===========================================
    // TOGGLES loaded from config.js

    const MAX_RESULTS = 25;
    const DEBOUNCE_MS = 100;

    // Toggle state management
    let toggleStates = {};
    let filtersDropdownOpen = false;

    function initToggles() {
      // Load saved states or use defaults
      const saved = safeStorage.getItem('toggleStates');
      if (saved) {
        try {
          toggleStates = JSON.parse(saved);
        } catch (e) {
          toggleStates = {};
        }
      }

      // Migrate old localStorage keys (showKnowledge, showAdvanced)
      const oldKnowledge = safeStorage.getItem('showKnowledge');
      const oldAdvanced = safeStorage.getItem('showAdvanced');
      if (oldKnowledge !== null && toggleStates['Knowledge'] === undefined) {
        toggleStates['Knowledge'] = oldKnowledge === 'true';
        safeStorage.removeItem('showKnowledge');
      }
      if (oldAdvanced !== null && toggleStates['Advanced'] === undefined) {
        toggleStates['Advanced'] = oldAdvanced === 'true';
        safeStorage.removeItem('showAdvanced');
      }

      // Ensure all configured toggles have a state
      TOGGLES.forEach(t => {
        if (toggleStates[t.tag] === undefined) {
          toggleStates[t.tag] = t.default;
        }
      });
      saveToggleStates();
      renderFiltersDropdown();
      updateFiltersBadge();
    }

    function saveToggleStates() {
      safeStorage.setItem('toggleStates', JSON.stringify(toggleStates));
    }

    function renderFiltersDropdown() {
      const dropdown = document.getElementById('filters-dropdown');
      if (TOGGLES.length === 0) {
        dropdown.innerHTML = '<div class="filters-empty">No filters configured</div>';
        return;
      }
      dropdown.innerHTML = TOGGLES.map(t => `
        <div class="filter-item ${toggleStates[t.tag] ? 'active' : ''}" data-tag="${t.tag}">
          <span class="checkbox">${toggleStates[t.tag] ? '[x]' : '[ ]'}</span>
          <span>${t.label}</span>
        </div>
      `).join('');
    }

    function toggleFilter(tag) {
      toggleStates[tag] = !toggleStates[tag];
      saveToggleStates();
      renderFiltersDropdown();
      updateFiltersBadge();
      try {
        performSearch(document.getElementById('search').value.trim());
      } catch (e) {
        console.error('Filter search failed:', e);
        // Force re-render on error
        const filtered = filterResults(commands);
        render(filtered.slice(0, MAX_RESULTS), filtered.length);
      }
    }

    function updateFiltersBadge() {
      const activeCount = TOGGLES.filter(t => toggleStates[t.tag]).length;
      const badge = document.getElementById('filters-badge');
      const toggle = document.getElementById('filters-toggle');
      badge.textContent = activeCount || '';
      badge.dataset.count = activeCount;
      toggle.classList.toggle('has-active', activeCount > 0);
    }

    function toggleFiltersDropdown() {
      filtersDropdownOpen = !filtersDropdownOpen;
      document.getElementById('filters-dropdown').classList.toggle('open', filtersDropdownOpen);
      document.getElementById('filters-toggle').classList.toggle('open', filtersDropdownOpen);
    }

    // Close dropdown when clicking outside
    document.addEventListener('click', (e) => {
      if (filtersDropdownOpen && !e.target.closest('.filters-container')) {
        filtersDropdownOpen = false;
        document.getElementById('filters-dropdown').classList.remove('open');
        document.getElementById('filters-toggle').classList.remove('open');
      }
    });

    // Initialize toggles
    initToggles();

    // Variable/workspace management
    let currentWorkspace = safeStorage.getItem('currentWorkspace') || 'default';
    let workspaces = JSON.parse(safeStorage.getItem('workspaces') || '{"default":{}}');
    let varPanelOpen = false;
    let analyzerPanelOpen = false;
    let historyPanelOpen = false;
    let copyHistory = JSON.parse(safeStorage.getItem('copyHistory') || '[]');

    // Migration for copy history (v2.5.5)
    function migrateCopyHistory() {
      if (copyHistory.length > 0 && typeof copyHistory[0] === 'string') {
        copyHistory = copyHistory.map(text => ({
          label: 'Legacy Copy',
          content: text
        }));
        safeStorage.setItem('copyHistory', JSON.stringify(copyHistory));
      }
    }
    migrateCopyHistory();

    function getWorkspaceVars() {
      return workspaces[currentWorkspace] || {};
    }

    function saveWorkspaces() {
      safeStorage.setItem('workspaces', JSON.stringify(workspaces));
      safeStorage.setItem('currentWorkspace', currentWorkspace);
    }

    function extractVariables(code) {
      const matches = code.match(/<(\w+)>/g) || [];
      return [...new Set(matches.map(m => m.slice(1, -1)))];
    }

    function getNoteContent(note) {
      return note?.content || '';
    }

    function noteToMarkdown(note) {
      // Convert note item to markdown format
      // Blockquotes get `> ` prefix, text is plain
      if (note?.type === 'note') return `> ${note.content}`;
      if (note?.type === 'text') return note.content;
      return '';
    }

    function notesToMarkdown(notes) {
      // Convert array of notes to markdown string
      if (!notes || !notes.length) return '';
      return notes.map(noteToMarkdown).join('\n') + '\n';
    }

    function substituteVariables(code) {
      const vars = getWorkspaceVars();
      let result = code;
      const missing = [];
      const found = extractVariables(code);

      found.forEach(varName => {
        const value = vars[varName];
        if (value !== undefined && value !== '') {
          result = result.replace(new RegExp(`<${varName}>`, 'g'), value);
        } else {
          missing.push(varName);
        }
      });

      return { text: result, missing };
    }

    function highlightVariables(code) {
      const vars = getWorkspaceVars();
      let result = escapeHtml(code);
      const found = extractVariables(code);

      found.forEach(varName => {
        const value = vars[varName];
        // After escapeHtml, < becomes < and > becomes >
        const escapedPattern = `<${varName}>`;
        if (value !== undefined && value !== '') {
          result = result.split(escapedPattern).join(`<span class="var-value">${escapeHtml(value)}</span>`);
        } else {
          result = result.split(escapedPattern).join(`<span class="var-missing"><${varName}></span>`);
        }
      });

      return result;
    }

    function getActiveVariables() {
      const allVars = new Set();

      // Only get variables from expanded procedures
      document.querySelectorAll('.procedure.expanded').forEach(procEl => {
        const index = parseInt(procEl.dataset.index);
        const item = currentResults[index];
        if (!item) return;

        const proc = item.item || item;
        // Extract from procedure-level notes
        if (proc.notes) {
          proc.notes.forEach(note => extractVariables(getNoteContent(note)).forEach(v => allVars.add(v)));
        }
        proc.steps.forEach(step => {
          // Extract from step codes
          if (step.codes) {
            step.codes.forEach(c => extractVariables(c.code).forEach(v => allVars.add(v)));
          }
          // Extract from step notes
          if (step.notes) {
            step.notes.forEach(note => extractVariables(getNoteContent(note)).forEach(v => allVars.add(v)));
          }
          if (step.postNotes) {
            step.postNotes.forEach(note => extractVariables(getNoteContent(note)).forEach(v => allVars.add(v)));
          }
          // Extract from substeps
          if (step.substeps) {
            step.substeps.forEach(substep => {
              if (substep.codes) {
                substep.codes.forEach(c => extractVariables(c.code).forEach(v => allVars.add(v)));
              }
              if (substep.notes) {
                substep.notes.forEach(note => extractVariables(getNoteContent(note)).forEach(v => allVars.add(v)));
              }
              if (substep.postNotes) {
                substep.postNotes.forEach(note => extractVariables(getNoteContent(note)).forEach(v => allVars.add(v)));
              }
            });
          }
        });
      });
      return [...allVars].sort();
    }

    function updateVarPanel() {
      const grid = document.getElementById('var-grid');
      const vars = getWorkspaceVars();
      const activeVars = getActiveVariables();

      // Always show variables that have values, plus variables from expanded notes
      const filledVars = Object.keys(vars).filter(k => vars[k] && vars[k].trim() !== '');
      const allVars = [...new Set([...filledVars, ...activeVars])].sort();

      if (allVars.length === 0) {
        grid.innerHTML = '<div class="var-empty">No variables detected. Expand a note to see its variables.</div>';
        return;
      }

      grid.innerHTML = allVars.map(varName => `
        <div class="var-field">
          <label data-var="${varName}">&lt;${varName}&gt;</label>
          <input
            type="text"
            value="${escapeHtml(vars[varName] || '')}"
            placeholder="Enter value..."
            data-var="${varName}"
          />
        </div>
      `).join('');
    }

    function showToast(message, type = 'success') {
      const toast = document.getElementById('toast');
      toast.textContent = message;
      toast.className = 'toast ' + type;
      setTimeout(() => toast.classList.add('show'), 10);
      setTimeout(() => toast.classList.remove('show'), 2000);
    }

    function copyVarValue(label, varName) {
      const value = getWorkspaceVars()[varName];
      if (!value) {
        showToast(`<${varName}> is empty`, 'error');
        return;
      }
      navigator.clipboard.writeText(value).then(() => {
        label.classList.add('copied');
        setTimeout(() => label.classList.remove('copied'), 1000);
        showToast(`Copied: ${value}`, 'success');
      });
    }

    function updateVariable(name, value) {
      if (!workspaces[currentWorkspace]) {
        workspaces[currentWorkspace] = {};
      }
      if (value === '') {
        delete workspaces[currentWorkspace][name];
      } else {
        workspaces[currentWorkspace][name] = value;
      }
      saveWorkspaces();
      updateWorkspaceButtons();
      // Only update expanded procedures for performance
      applyVariableHighlighting(true);
    }

    function updateWorkspaceSelect() {
      const select = document.getElementById('workspace-select');
      select.innerHTML = Object.keys(workspaces).sort().map(name =>
        `<option value="${escapeHtml(name)}" ${name === currentWorkspace ? 'selected' : ''}>${escapeHtml(name)}</option>`
      ).join('');
      updateWorkspaceButtons();
    }

    function updateWorkspaceButtons() {
      const workspaceCount = Object.keys(workspaces).length;
      document.getElementById('delete-btn').disabled = workspaceCount <= 1;

      // Update badge with variable count
      const varCount = Object.keys(getWorkspaceVars()).filter(k => getWorkspaceVars()[k]).length;
      const badge = document.getElementById('var-badge');
      badge.textContent = varCount || '';
      badge.dataset.count = varCount;
    }

    function switchWorkspace(name) {
      currentWorkspace = name;
      saveWorkspaces();
      updateVarPanel();
      updateWorkspaceButtons();
      applyVariableHighlighting(true);
    }

    function createWorkspace() {
      openModal('New Workspace', 'Enter workspace name...', (name) => {
        if (workspaces[name]) {
          openModal('Workspace Exists', 'Choose a different name...', createWorkspaceWithName);
          return;
        }
        createWorkspaceWithName(name);
      });
    }

    function createWorkspaceWithName(name) {
      workspaces[name] = {};
      currentWorkspace = name;
      saveWorkspaces();
      updateWorkspaceSelect();
      updateVarPanel();
      render(currentResults);
    }

    function renameWorkspace() {
      openModalWithValue('Rename Workspace', 'New name...', currentWorkspace, (newName) => {
        if (newName === currentWorkspace) return;
        if (workspaces[newName]) {
          return;
        }
        workspaces[newName] = workspaces[currentWorkspace];
        delete workspaces[currentWorkspace];
        currentWorkspace = newName;
        saveWorkspaces();
        updateWorkspaceSelect();
      });
    }

    function deleteWorkspace() {
      const workspaceNames = Object.keys(workspaces);
      if (workspaceNames.length <= 1) {
        return;
      }
      openConfirm(`Delete "${currentWorkspace}"?`, () => {
        delete workspaces[currentWorkspace];
        currentWorkspace = Object.keys(workspaces)[0];
        saveWorkspaces();
        updateWorkspaceSelect();
        updateVarPanel();
        applyVariableHighlighting();
      });
    }

    function clearAllVariables() {
      const vars = getWorkspaceVars();
      if (Object.keys(vars).length === 0) {
        showToast('No variables to clear', 'error');
        return;
      }
      openConfirm('Clear all variables?', () => {
        workspaces[currentWorkspace] = {};
        saveWorkspaces();
        updateVarPanel();
        updateWorkspaceButtons();
        applyVariableHighlighting(true);
        showToast('All variables cleared', 'success');
      });
    }

    function addVariable() {
      openModal('New Variable', 'Variable name...', (name) => {
        if (!/^\w+$/.test(name)) return;
        if (!workspaces[currentWorkspace]) {
          workspaces[currentWorkspace] = {};
        }
        if (workspaces[currentWorkspace][name] === undefined) {
          workspaces[currentWorkspace][name] = '';
        }
        saveWorkspaces();
        updateVarPanel();
        // Focus the new input
        setTimeout(() => {
          const input = document.querySelector(`input[data-var="${name}"]`);
          if (input) input.focus();
        }, 0);
      });
    }

    function toggleVarPanel() {
      varPanelOpen = !varPanelOpen;
      document.getElementById('var-panel').classList.toggle('open', varPanelOpen);
      document.querySelector('.var-toggle').classList.toggle('active', varPanelOpen);
      if (varPanelOpen) {
        updateVarPanel();
        if (historyPanelOpen) toggleHistoryPanel();
        if (analyzerPanelOpen) toggleAnalyzerPanel();
      }
    }

    // Copy History functions
    function toggleHistoryPanel() {
      historyPanelOpen = !historyPanelOpen;
      document.getElementById('history-panel').classList.toggle('open', historyPanelOpen);
      document.getElementById('history-toggle').classList.toggle('active', historyPanelOpen);
      if (historyPanelOpen) {
        updateHistoryPanel();
        if (varPanelOpen) toggleVarPanel();
        if (analyzerPanelOpen) toggleAnalyzerPanel();
      }
    }

    function addToHistory(item) {
      if (!item || !item.content) return;
      // Remove if already exists (to move to top) - compare by content
      copyHistory = copyHistory.filter(h => h.content !== item.content);
      copyHistory.unshift(item);
      if (copyHistory.length > 10) copyHistory.pop();
      safeStorage.setItem('copyHistory', JSON.stringify(copyHistory));
      if (historyPanelOpen) updateHistoryPanel();
    }

    function updateHistoryPanel() {
      const list = document.getElementById('history-list');
      if (copyHistory.length === 0) {
        list.innerHTML = '<div class="history-empty">No copy history yet.</div>';
        return;
      }
      list.innerHTML = copyHistory.map((item, i) => `
        <div class="history-item" data-index="${i}">
          <div class="history-item-label">${escapeHtml(item.label)}</div>
          <div class="history-item-preview">${escapeHtml(item.content.substring(0, 200))}${item.content.length > 200 ? '...' : ''}</div>
        </div>
      `).join('');
    }

    function copyHistoryItem(index) {
      const item = copyHistory[index];
      navigator.clipboard.writeText(item.content).then(() => {
        showToast('Copied from history!', 'success');
        // Move to top
        addToHistory(item);
      });
    }

    function clearHistory() {
      openConfirm('Clear copy history?', () => {
        copyHistory = [];
        safeStorage.setItem('copyHistory', JSON.stringify(copyHistory));
        updateHistoryPanel();
        showToast('History cleared', 'success');
      });
    }

    // Text Analyzer functions
    function toggleAnalyzerPanel() {
      analyzerPanelOpen = !analyzerPanelOpen;
      document.getElementById('analyzer-panel').classList.toggle('open', analyzerPanelOpen);
      document.getElementById('analyzer-toggle').classList.toggle('active', analyzerPanelOpen);
      if (analyzerPanelOpen) {
        if (varPanelOpen) toggleVarPanel();
        if (historyPanelOpen) toggleHistoryPanel();
      }
    }

    function classifyChar(char) {
      const code = char.charCodeAt(0);
      if (code >= 65 && code <= 90) return 'upper';
      if (code >= 97 && code <= 122) return 'lower';
      if (code >= 48 && code <= 57) return 'digit';
      if (/\s/.test(char)) return 'whitespace';
      return 'special';
    }

    function getWhitespaceMarker(char) {
      if (char === ' ') return '\u00B7';
      if (char === '\t') return '\u2192';
      if (char === '\n' || char === '\r') return '\u21B5';
      return '\u2423';
    }

    function updateAnalyzer() {
      const input = document.getElementById('analyzer-input').value;
      const charsEl = document.getElementById('analyzer-chars');
      const hashEl = document.getElementById('analyzer-hash');

      if (!input) {
        charsEl.innerHTML = '';
        hashEl.textContent = '-';
        hashEl.classList.remove('copied');
        return;
      }

      let html = '';
      for (const char of input) {
        const type = classifyChar(char);
        if (type === 'whitespace') {
          html += `<span class="char-${type}">${getWhitespaceMarker(char)}</span>`;
          if (char === '\n') html += '<br>';
        } else {
          html += `<span class="char-${type}">${escapeHtml(char)}</span>`;
        }
      }
      charsEl.innerHTML = html;

      hashEl.textContent = md5(input);
      hashEl.classList.remove('copied');
    }

    function copyAnalyzerHash() {
      const hash = document.getElementById('analyzer-hash').textContent;
      if (hash === '-') return;
      navigator.clipboard.writeText(hash).then(() => {
        document.getElementById('analyzer-hash').classList.add('copied');
        showToast('MD5 copied!', 'success');
        setTimeout(() => document.getElementById('analyzer-hash').classList.remove('copied'), 1500);
      });
    }

    function clearAnalyzer() {
      document.getElementById('analyzer-input').value = '';
      updateAnalyzer();
    }

    // MD5 hash implementation (RFC 1321)
    function md5(string) {
      function rotateLeft(x, n) {
        return (x << n) | (x >>> (32 - n));
      }

      function addUnsigned(x, y) {
        const x8 = x & 0x80000000;
        const y8 = y & 0x80000000;
        const x4 = x & 0x40000000;
        const y4 = y & 0x40000000;
        const result = (x & 0x3FFFFFFF) + (y & 0x3FFFFFFF);
        if (x4 & y4) return result ^ 0x80000000 ^ x8 ^ y8;
        if (x4 | y4) {
          if (result & 0x40000000) return result ^ 0xC0000000 ^ x8 ^ y8;
          return result ^ 0x40000000 ^ x8 ^ y8;
        }
        return result ^ x8 ^ y8;
      }

      function F(x, y, z) { return (x & y) | (~x & z); }
      function G(x, y, z) { return (x & z) | (y & ~z); }
      function H(x, y, z) { return x ^ y ^ z; }
      function I(x, y, z) { return y ^ (x | ~z); }

      function FF(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      function GG(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      function HH(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }
      function II(a, b, c, d, x, s, ac) {
        a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
        return addUnsigned(rotateLeft(a, s), b);
      }

      function convertToWordArray(str) {
        let lWordCount;
        const lMessageLength = str.length;
        const lNumberOfWords_temp1 = lMessageLength + 8;
        const lNumberOfWords_temp2 = (lNumberOfWords_temp1 - (lNumberOfWords_temp1 % 64)) / 64;
        const lNumberOfWords = (lNumberOfWords_temp2 + 1) * 16;
        const lWordArray = new Array(lNumberOfWords - 1);
        let lBytePosition = 0;
        let lByteCount = 0;
        while (lByteCount < lMessageLength) {
          lWordCount = (lByteCount - (lByteCount % 4)) / 4;
          lBytePosition = (lByteCount % 4) * 8;
          lWordArray[lWordCount] = (lWordArray[lWordCount] || 0) | (str.charCodeAt(lByteCount) << lBytePosition);
          lByteCount++;
        }
        lWordCount = (lByteCount - (lByteCount % 4)) / 4;
        lBytePosition = (lByteCount % 4) * 8;
        lWordArray[lWordCount] = (lWordArray[lWordCount] || 0) | (0x80 << lBytePosition);
        lWordArray[lNumberOfWords - 2] = lMessageLength << 3;
        lWordArray[lNumberOfWords - 1] = lMessageLength >>> 29;
        return lWordArray;
      }

      function wordToHex(lValue) {
        let WordToHexValue = '', WordToHexValue_temp = '', lByte, lCount;
        for (lCount = 0; lCount <= 3; lCount++) {
          lByte = (lValue >>> (lCount * 8)) & 255;
          WordToHexValue_temp = '0' + lByte.toString(16);
          WordToHexValue = WordToHexValue + WordToHexValue_temp.substr(WordToHexValue_temp.length - 2, 2);
        }
        return WordToHexValue;
      }

      const utf8String = unescape(encodeURIComponent(string));
      const x = convertToWordArray(utf8String);
      let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;

      const S11 = 7, S12 = 12, S13 = 17, S14 = 22;
      const S21 = 5, S22 = 9, S23 = 14, S24 = 20;
      const S31 = 4, S32 = 11, S33 = 16, S34 = 23;
      const S41 = 6, S42 = 10, S43 = 15, S44 = 21;

      for (let k = 0; k < x.length; k += 16) {
        const AA = a, BB = b, CC = c, DD = d;
        a = FF(a, b, c, d, x[k + 0], S11, 0xD76AA478);
        d = FF(d, a, b, c, x[k + 1], S12, 0xE8C7B756);
        c = FF(c, d, a, b, x[k + 2], S13, 0x242070DB);
        b = FF(b, c, d, a, x[k + 3], S14, 0xC1BDCEEE);
        a = FF(a, b, c, d, x[k + 4], S11, 0xF57C0FAF);
        d = FF(d, a, b, c, x[k + 5], S12, 0x4787C62A);
        c = FF(c, d, a, b, x[k + 6], S13, 0xA8304613);
        b = FF(b, c, d, a, x[k + 7], S14, 0xFD469501);
        a = FF(a, b, c, d, x[k + 8], S11, 0x698098D8);
        d = FF(d, a, b, c, x[k + 9], S12, 0x8B44F7AF);
        c = FF(c, d, a, b, x[k + 10], S13, 0xFFFF5BB1);
        b = FF(b, c, d, a, x[k + 11], S14, 0x895CD7BE);
        a = FF(a, b, c, d, x[k + 12], S11, 0x6B901122);
        d = FF(d, a, b, c, x[k + 13], S12, 0xFD987193);
        c = FF(c, d, a, b, x[k + 14], S13, 0xA679438E);
        b = FF(b, c, d, a, x[k + 15], S14, 0x49B40821);
        a = GG(a, b, c, d, x[k + 1], S21, 0xF61E2562);
        d = GG(d, a, b, c, x[k + 6], S22, 0xC040B340);
        c = GG(c, d, a, b, x[k + 11], S23, 0x265E5A51);
        b = GG(b, c, d, a, x[k + 0], S24, 0xE9B6C7AA);
        a = GG(a, b, c, d, x[k + 5], S21, 0xD62F105D);
        d = GG(d, a, b, c, x[k + 10], S22, 0x02441453);
        c = GG(c, d, a, b, x[k + 15], S23, 0xD8A1E681);
        b = GG(b, c, d, a, x[k + 4], S24, 0xE7D3FBC8);
        a = GG(a, b, c, d, x[k + 9], S21, 0x21E1CDE6);
        d = GG(d, a, b, c, x[k + 14], S22, 0xC33707D6);
        c = GG(c, d, a, b, x[k + 3], S23, 0xF4D50D87);
        b = GG(b, c, d, a, x[k + 8], S24, 0x455A14ED);
        a = GG(a, b, c, d, x[k + 13], S21, 0xA9E3E905);
        d = GG(d, a, b, c, x[k + 2], S22, 0xFCEFA3F8);
        c = GG(c, d, a, b, x[k + 7], S23, 0x676F02D9);
        b = GG(b, c, d, a, x[k + 12], S24, 0x8D2A4C8A);
        a = HH(a, b, c, d, x[k + 5], S31, 0xFFFA3942);
        d = HH(d, a, b, c, x[k + 8], S32, 0x8771F681);
        c = HH(c, d, a, b, x[k + 11], S33, 0x6D9D6122);
        b = HH(b, c, d, a, x[k + 14], S34, 0xFDE5380C);
        a = HH(a, b, c, d, x[k + 1], S31, 0xA4BEEA44);
        d = HH(d, a, b, c, x[k + 4], S32, 0x4BDECFA9);
        c = HH(c, d, a, b, x[k + 7], S33, 0xF6BB4B60);
        b = HH(b, c, d, a, x[k + 10], S34, 0xBEBFBC70);
        a = HH(a, b, c, d, x[k + 13], S31, 0x289B7EC6);
        d = HH(d, a, b, c, x[k + 0], S32, 0xEAA127FA);
        c = HH(c, d, a, b, x[k + 3], S33, 0xD4EF3085);
        b = HH(b, c, d, a, x[k + 6], S34, 0x04881D05);
        a = HH(a, b, c, d, x[k + 9], S31, 0xD9D4D039);
        d = HH(d, a, b, c, x[k + 12], S32, 0xE6DB99E5);
        c = HH(c, d, a, b, x[k + 15], S33, 0x1FA27CF8);
        b = HH(b, c, d, a, x[k + 2], S34, 0xC4AC5665);
        a = II(a, b, c, d, x[k + 0], S41, 0xF4292244);
        d = II(d, a, b, c, x[k + 7], S42, 0x432AFF97);
        c = II(c, d, a, b, x[k + 14], S43, 0xAB9423A7);
        b = II(b, c, d, a, x[k + 5], S44, 0xFC93A039);
        a = II(a, b, c, d, x[k + 12], S41, 0x655B59C3);
        d = II(d, a, b, c, x[k + 3], S42, 0x8F0CCC92);
        c = II(c, d, a, b, x[k + 10], S43, 0xFFEFF47D);
        b = II(b, c, d, a, x[k + 1], S44, 0x85845DD1);
        a = II(a, b, c, d, x[k + 8], S41, 0x6FA87E4F);
        d = II(d, a, b, c, x[k + 15], S42, 0xFE2CE6E0);
        c = II(c, d, a, b, x[k + 6], S43, 0xA3014314);
        b = II(b, c, d, a, x[k + 13], S44, 0x4E0811A1);
        a = II(a, b, c, d, x[k + 4], S41, 0xF7537E82);
        d = II(d, a, b, c, x[k + 11], S42, 0xBD3AF235);
        c = II(c, d, a, b, x[k + 2], S43, 0x2AD7D2BB);
        b = II(b, c, d, a, x[k + 9], S44, 0xEB86D391);
        a = addUnsigned(a, AA);
        b = addUnsigned(b, BB);
        c = addUnsigned(c, CC);
        d = addUnsigned(d, DD);
      }

      return (wordToHex(a) + wordToHex(b) + wordToHex(c) + wordToHex(d)).toLowerCase();
    }

    // Initialize workspace UI
    updateWorkspaceSelect();

    // CSP-friendly event listeners
    document.getElementById('title').addEventListener('click', toggleTheme);
    document.getElementById('var-toggle').addEventListener('click', toggleVarPanel);
    document.getElementById('history-toggle').addEventListener('click', toggleHistoryPanel);
    document.getElementById('workspace-select').addEventListener('change', (e) => switchWorkspace(e.target.value));
    document.getElementById('new-workspace-btn').addEventListener('click', createWorkspace);
    document.getElementById('rename-btn').addEventListener('click', renameWorkspace);
    document.getElementById('delete-btn').addEventListener('click', deleteWorkspace);
    document.getElementById('analyzer-toggle').addEventListener('click', toggleAnalyzerPanel);
    document.getElementById('filters-toggle').addEventListener('click', toggleFiltersDropdown);
    document.getElementById('add-var-btn').addEventListener('click', addVariable);
    document.getElementById('clear-vars-btn').addEventListener('click', clearAllVariables);
    document.getElementById('clear-history-btn').addEventListener('click', clearHistory);
    document.getElementById('analyzer-input').addEventListener('input', updateAnalyzer);
    document.getElementById('analyzer-hash').addEventListener('click', copyAnalyzerHash);
    document.getElementById('clear-analyzer-btn').addEventListener('click', clearAnalyzer);
    document.getElementById('modal-overlay').addEventListener('click', closeModal);
    document.getElementById('modal-content').addEventListener('click', (e) => e.stopPropagation());
    document.getElementById('modal-cancel-btn').addEventListener('click', closeModal);
    document.getElementById('modal-confirm-btn').addEventListener('click', confirmModal);
    document.getElementById('confirm-overlay').addEventListener('click', closeConfirm);
    document.getElementById('confirm-content').addEventListener('click', (e) => e.stopPropagation());
    document.getElementById('confirm-cancel-btn').addEventListener('click', closeConfirm);
    document.getElementById('confirm-do-btn').addEventListener('click', doConfirm);

    // Event delegation for dynamic elements
    document.getElementById('filters-dropdown').addEventListener('click', (e) => {
      const item = e.target.closest('.filter-item');
      if (item) {
        e.stopPropagation();
        toggleFilter(item.dataset.tag);
      }
    });

    document.getElementById('var-grid').addEventListener('click', (e) => {
      const label = e.target.closest('label');
      if (label) {
        copyVarValue(label, label.dataset.var);
      }
    });

    document.getElementById('var-grid').addEventListener('input', (e) => {
      const input = e.target.closest('input');
      if (input) {
        updateVariable(input.dataset.var, input.value);
      }
    });

    document.getElementById('history-list').addEventListener('click', (e) => {
      const item = e.target.closest('.history-item');
      if (item) {
        copyHistoryItem(parseInt(item.dataset.index));
      }
    });

    document.getElementById('results').addEventListener('click', (e) => {
      // Procedure header toggle
      const header = e.target.closest('.procedure-header');
      if (header && !e.target.closest('button')) {
        const proc = header.closest('.procedure');
        toggleProcedure(parseInt(proc.dataset.index));
        return;
      }

      // Copy All button (procedure level)
      const copyAllBtn = e.target.closest('.copy-all-btn');
      if (copyAllBtn) {
        e.stopPropagation();
        copyAll(copyAllBtn, parseInt(copyAllBtn.dataset.index));
        return;
      }

      // Copy button (step level)
      const copyBtn = e.target.closest('.copy-btn');
      if (copyBtn) {
        e.stopPropagation();
        copyCode(copyBtn, parseInt(copyBtn.dataset.index), parseInt(copyBtn.dataset.step));
        return;
      }

      // Code block copy
      const codeBlock = e.target.closest('.code-block');
      if (codeBlock) {
        copyBlock(codeBlock);
        return;
      }
    });

    // Modal functions
    let modalCallback = null;

    function openModal(title, placeholder, callback) {
      openModalWithValue(title, placeholder, '', callback);
    }

    function openModalWithValue(title, placeholder, value, callback) {
      modalCallback = callback;
      document.getElementById('modal-title').textContent = title;
      document.getElementById('modal-input').placeholder = placeholder || '';
      document.getElementById('modal-input').value = value || '';
      document.getElementById('modal-overlay').classList.add('open');
      setTimeout(() => {
        const input = document.getElementById('modal-input');
        input.focus();
        input.select();
      }, 50);
    }

    function closeModal() {
      document.getElementById('modal-overlay').classList.remove('open');
      modalCallback = null;
    }

    function confirmModal() {
      const value = document.getElementById('modal-input').value.trim();
      if (value && modalCallback) {
        modalCallback(value);
      }
      closeModal();
    }

    // Handle Enter key in modal
    document.getElementById('modal-input').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        confirmModal();
      } else if (e.key === 'Escape') {
        e.preventDefault();
        closeModal();
      }
    });

    // Confirm modal functions
    let confirmCallback = null;

    function openConfirm(title, callback) {
      confirmCallback = callback;
      document.getElementById('confirm-title').textContent = title;
      document.getElementById('confirm-overlay').classList.add('open');
    }

    function closeConfirm() {
      document.getElementById('confirm-overlay').classList.remove('open');
      confirmCallback = null;
    }

    function doConfirm() {
      if (confirmCallback) {
        confirmCallback();
      }
      closeConfirm();
    }

    // Register service worker for offline support (wrapped in try/catch for restricted environments)
    try {
      if ('serviceWorker' in navigator) {
        navigator.serviceWorker.register('./sw.js').catch(err => {
          console.warn('Service Worker registration failed:', err.message);
        });
      }
    } catch (e) {
      console.warn('Service Worker not available:', e.message);
    }

    console.log('SURGE: Initializing app...');
    let commands = [];
    let fuse = null;
    let selectedIndex = 0;
    let currentResults = []; // Cache current search results
    let searchTimeout = null; // For debouncing

    // Load commands
    console.log('SURGE: Fetching commands.json...');
    console.log('SURGE: Environment Check:', {
      location: window.location.href,
      protocol: window.location.protocol,
      localStorageAvailable: (function() {
        try {
          localStorage.setItem('test', 'test');
          localStorage.removeItem('test');
          return true;
        } catch(e) { return false; }
      })(),
      serviceWorkerAvailable: 'serviceWorker' in navigator
    });

    fetch('commands.json')
      .then(res => {
        console.log('SURGE: Fetch response received:', res.status, res.statusText);
        const contentType = res.headers.get('content-type');
        console.log('SURGE: Content-Type:', contentType);
        
        if (!res.ok) {
          if (res.status === 404) {
            console.error('SURGE: commands.json not found. Did you run build.py?');
          }
          throw new Error(`HTTP error! status: ${res.status} ${res.statusText}`);
        }
        
        // Check if proxy returned an HTML error page instead of JSON
        if (contentType && !contentType.includes('application/json')) {
          console.warn('SURGE: Expected JSON but got', contentType, '. This might be a proxy block page.');
        }
        
        return res.json();
      })
      .then(data => {
        console.log('SURGE: Commands loaded successfully, count:', data.length);
        commands = data;
        if (typeof Fuse === 'undefined') {
          console.error('SURGE: Fuse is NOT defined!');
          throw new Error('Fuse library not loaded');
        }
        fuse = new Fuse(commands, {
          keys: [
            { name: 'title', weight: 2 },
            { name: 'category', weight: 1.5 },
            { name: 'tags', weight: 1 },
            { name: 'notes', weight: 0.8 },
            { name: 'steps.notes', weight: 0.8 },
            { name: 'resources.text', weight: 0.8 },
            { name: 'resources.url', weight: 0.5 },
            { name: 'steps.title', weight: 0.5 },
            { name: 'steps.codes.code', weight: 0.3 }
          ],
          threshold: 0.4,
          includeScore: true
        });
        const filtered = filterResults(commands);
        render(filtered.slice(0, MAX_RESULTS), filtered.length);
      })
      .catch(err => {
        console.error('SURGE: Error loading commands:', err);
        document.getElementById('results').innerHTML =
          `<div class="no-results">Failed to load commands: ${err.message}. Run build.py first.</div>`;
      });

    function render(items, totalCount = 0) {
      const resultsEl = document.getElementById('results');
      currentResults = items; // Cache for copy functions
      totalCount = totalCount || items.length;

      if (items.length === 0) {
        resultsEl.innerHTML = '<div class="no-results">No matching commands</div>';
        return;
      }

      resultsEl.innerHTML = items.map((item, index) => {
        const proc = item.item || item;
        const stepsHtml = (proc.steps || []).map((step, stepIndex) => {
          if (step.substeps) {
            // Step with sub-steps
            const substepsHtml = step.substeps.map((substep, substepIndex) => {
              const substepClasses = `substep${substep.optional ? ' optional' : ''}${substep.alternative ? ' alternative' : ''}`;
              return `
              <div class="${substepClasses}">
                <div class="substep-header">
                  <span class="substep-title">${getStepLabel(substep)}${escapeHtml(substep.title)}</span>
                </div>
                ${renderContent(substep.notes, 'step')}
                ${substep.codes && substep.codes.length ? substep.codes.map(c => `<div class="code-block" data-lang="${c.lang}">
                <pre><code class="language-${c.lang}">${escapeHtml(c.code)}</code></pre>
              </div>`).join('') : ''}
                ${renderContent(substep.postNotes, 'step', true)}
              </div>
            `;}).join('');

            const stepContainerClasses = `step has-substeps${step.optional ? ' optional' : ''}${step.alternative ? ' alternative' : ''}`;
            return `
              <div class="${stepContainerClasses}">
                <div class="step-header">
                  <span class="step-title">${getStepLabel(step)}${escapeHtml(step.title)}</span>
                  <button class="copy-btn" data-index="${index}" data-step="${stepIndex}">Copy All</button>
                </div>
                ${renderContent(step.notes, 'step')}
                ${step.codes ? step.codes.map(c => `<div class="code-block" data-lang="${c.lang}">
                  <pre><code class="language-${c.lang}">${escapeHtml(c.code)}</code></pre>
                </div>`).join('') : ''}
                <div class="substeps">${substepsHtml}</div>
              </div>
            `;
          } else {
            // Regular step with direct code blocks
            const stepContainerClasses = `step${step.optional ? ' optional' : ''}${step.alternative ? ' alternative' : ''}`;
            return `
              <div class="${stepContainerClasses}">
                <div class="step-header">
                  <span class="step-title">${getStepLabel(step)}${escapeHtml(step.title)}</span>
                </div>
                ${renderContent(step.notes, 'step')}
                ${step.codes && step.codes.length ? step.codes.map(c => `<div class="code-block" data-lang="${c.lang}">
                  <pre><code class="language-${c.lang}">${escapeHtml(c.code)}</code></pre>
                </div>`).join('') : ''}
                ${renderContent(step.postNotes, 'step', true)}
              </div>
            `;
          }
        }).join('');

        // Filter out tags that are used as filters (they're redundant to display)
        const filterTags = TOGGLES.map(t => t.tag);
        const displayTags = proc.tags.filter(t => !filterTags.includes(t));
        const tagsHtml = displayTags.length > 0
          ? `<div class="tags">${displayTags.map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('')}</div>`
          : '';

        const resourcesHtml = proc.resources && proc.resources.length > 0
          ? `<div class="resources">
              <span class="resources-label">Resources:</span>
              ${proc.resources.map(r => `<a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r.text)}</a>`).join(' · ')}
            </div>`
          : '';

        const notesHtml = proc.notes && proc.notes.length
          ? renderContent(proc.notes, 'procedure') + '<hr class="notes-divider">'
          : '';

        // Get filter labels for this procedure
        const filterLabels = TOGGLES
          .filter(t => proc[t.tag.toLowerCase()])
          .map(t => t.label);
        const filterLabelHtml = filterLabels.length
          ? `<div class="filter-label">${filterLabels.join(' · ')}</div>`
          : '';

        return `
          <div class="procedure ${index === selectedIndex ? 'selected' : ''}" data-index="${index}">
            <div class="procedure-header">
              <div>
                <div class="procedure-title">${escapeHtml(proc.title)}</div>
                <div class="procedure-meta">
                  <span class="category-badge">${escapeHtml(proc.category)}</span>
                  <span class="step-count">${(proc.steps || []).length} step${(proc.steps || []).length !== 1 ? 's' : ''}</span>
                </div>
                ${tagsHtml}
              </div>
              <button class="copy-all-btn" data-index="${index}">Copy All</button>
            </div>
            <div class="procedure-body">
              <div>
                ${resourcesHtml}
                ${notesHtml}
                ${stepsHtml}
              </div>
            </div>
            ${filterLabelHtml}
          </div>
        `;
      }).join('');

      // Show message if results are truncated
      if (totalCount > items.length) {
        resultsEl.innerHTML += `<div class="results-limit">Showing ${items.length} of ${totalCount} results. Refine your search to see more.</div>`;
      }

      updateSelection();
      // Only highlight unhighlighted code blocks
      // Apply variable highlighting to all procedures (handles both hljs and variables)
      applyVariableHighlighting(false);
      // Update variable panel if open
      if (varPanelOpen) {
        updateVarPanel();
      }
    }

    function applyVariableHighlighting(expandedOnly = false) {
      const selector = expandedOnly ? '.procedure.expanded' : '.procedure';
      document.querySelectorAll(selector).forEach(procEl => {
        const procIndex = parseInt(procEl.dataset.index);
        applyVariableHighlightingForProcedure(procEl, procIndex);
      });
    }

    function escapeHtml(text) {
      return text
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '"');
    }

    function getStepLabel(item) {
      let label = '';
      if (item.optional) label += '<span class="label-optional">(optional)</span> ';
      if (item.alternative) label += '<span class="label-alternative">(alternative)</span> ';
      if (item.remote) label += '<span class="label-remote">[Remote]</span> ';
      if (item.local) label += '<span class="label-local">[Local]</span> ';
      return label;
    }

    function parseNotesMarkdown(text) {
      const vars = getWorkspaceVars();

      // Process line by line for block-level elements
      const lines = text.split('\n');
      const processed = [];
      let inList = false;
      let listType = null;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Horizontal rule (3+ dashes, asterisks, or underscores)
        if (/^[-*_]{3,}$/.test(line.trim())) {
          if (inList) {
            processed.push(listType === 'ul' ? '</ul>' : '</ol>');
            inList = false;
            listType = null;
          }
          processed.push('<hr class="note-hr">');
          continue;
        }

        // Unordered list item
        const ulMatch = line.match(/^[-*]\s+(.+)$/);
        if (ulMatch) {
          if (!inList || listType !== 'ul') {
            if (inList) processed.push(listType === 'ul' ? '</ul>' : '</ol>');
            processed.push('<ul>');
            inList = true;
            listType = 'ul';
          }
          processed.push(`<li>${ulMatch[1]}</li>`);
          continue;
        }

        // Ordered list item
        const olMatch = line.match(/^\d+\.\s+(.+)$/);
        if (olMatch) {
          if (!inList || listType !== 'ol') {
            if (inList) processed.push(listType === 'ul' ? '</ul>' : '</ol>');
            processed.push('<ol>');
            inList = true;
            listType = 'ol';
          }
          processed.push(`<li>${olMatch[1]}</li>`);
          continue;
        }

        // Regular line - close any open list
        if (inList) {
          processed.push(listType === 'ul' ? '</ul>' : '</ol>');
          inList = false;
          listType = null;
        }
        processed.push(line);
      }

      // Close any remaining open list
      if (inList) {
        processed.push(listType === 'ul' ? '</ul>' : '</ol>');
      }

      // Join and continue with inline processing
      let result = processed.join('\n');

      // Escape HTML (but preserve our tags)
      result = result.replace(/<(ul|\/ul|ol|\/ol|li|\/li|hr[^>]*)>/g, '\x00$1\x00');
      result = escapeHtml(result);
      result = result.replace(/\x00([^\x00]+)\x00/g, '<$1>');

      // Parse **bold** or __bold__
      result = result.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
      result = result.replace(/__(.+?)__/g, '<strong>$1</strong>');
      // Parse *italic* or _italic_ (but not inside words)
      result = result.replace(/(?<!\w)\*([^*]+?)\*(?!\w)/g, '<em>$1</em>');
      result = result.replace(/(?<!\w)_([^_]+?)_(?!\w)/g, '<em>$1</em>');
      // Parse `code`
      result = result.replace(/`([^`]+?)`/g, '<code>$1</code>');
      // Parse [text](url) links
      result = result.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank" rel="noopener" class="note-link">$1</a>');
      // Highlight variables (after escapeHtml, < becomes < and > becomes >)
      result = result.replace(/<(\w+)>/g, (match, varName) => {
        const value = vars[varName];
        if (value !== undefined && value !== '') {
          return `<span class="var-value">${escapeHtml(value)}</span>`;
        } else {
          return `<span class="var-missing"><${varName}></span>`;
        }
      });
      // Convert remaining newlines to <br> (but not inside lists)
      result = result.replace(/\n(?!<\/?[uo]l|<\/?li|<hr)/g, '<br>');
      // Clean up extra newlines around block elements
      result = result.replace(/\n?(<\/?[uo]l>|<li>|<\/li>|<hr[^>]*>)\n?/g, '$1');
      return result;
    }

    function renderContent(items, level = 'procedure', post = false) {
      // Render content items (notes and text) based on type
      // level: 'procedure' | 'step' determines CSS class
      // post: true for post-code content
      if (!items || !items.length) return '';
      return items.map(item => {
        if (item.type === 'note') {
          const cls = level === 'procedure' ? 'notes' : 'step-notes';
          const variant = item.variant ? ` ${item.variant}` : '';
          const postCls = post ? ' post-notes' : '';
          return `<div class="${cls}${variant}${postCls}">${parseNotesMarkdown(item.content)}</div>`;
        } else if (item.type === 'text') {
          const cls = level === 'procedure' ? 'prose' : 'step-prose';
          return `<div class="${cls}${post ? ' post-prose' : ''}">${parseNotesMarkdown(item.content)}</div>`;
        }
        return '';
      }).join('');
    }

    function toggleProcedure(index) {
      const procEl = document.querySelector(`.procedure[data-index="${index}"]`);
      const wasExpanded = procEl.classList.contains('expanded');
      procEl.classList.toggle('expanded');
      selectedIndex = index;
      updateSelection();
      // Apply variable highlighting when expanding
      if (!wasExpanded) {
        applyVariableHighlightingForProcedure(procEl, index);
      }
      // Update variable panel to show only expanded procedures' variables
      if (varPanelOpen) {
        updateVarPanel();
      }
    }

    function applyVariableHighlightingForProcedure(procEl, procIndex) {
      const vars = getWorkspaceVars();
      const proc = currentResults[procIndex]?.item || currentResults[procIndex];
      if (!proc) return;

      // Update procedure-level notes
      const procNotesEls = procEl.querySelectorAll(':scope > .procedure-body > div > .notes');
      if (proc.notes) {
        procNotesEls.forEach((noteEl, i) => {
          const note = proc.notes[i];
          if (note) {
            const text = typeof note === 'string' ? note : note.content;
            noteEl.innerHTML = parseNotesMarkdown(text);
          }
        });
      }

      procEl.querySelectorAll('.step').forEach((stepEl, stepIndex) => {
        const step = proc.steps[stepIndex];
        if (!step) return;

        // Update step notes
        const stepNotesEls = stepEl.querySelectorAll('.step-notes:not(.post-notes)');
        if (step.notes) {
          stepNotesEls.forEach((noteEl, i) => {
            const note = step.notes[i];
            if (note) {
              const text = typeof note === 'string' ? note : note.content;
              noteEl.innerHTML = parseNotesMarkdown(text);
            }
          });
        }

        // Update post-notes
        const postNotesEls = stepEl.querySelectorAll('.step-notes.post-notes');
        if (step.postNotes) {
          postNotesEls.forEach((noteEl, i) => {
            const note = step.postNotes[i];
            if (note) {
              const text = typeof note === 'string' ? note : note.content;
              noteEl.innerHTML = parseNotesMarkdown(text);
            }
          });
        }

        // Helper to highlight a code element
        function highlightCodeEl(codeEl, codeData) {
          let code = codeData.code;
          const lang = codeData.lang || 'bash';
          const varPattern = /<(\w+)>/g;

          // Create placeholders that won't be affected by syntax highlighting
          // We use a prefix that is unlikely to be split by hljs
          const placeholders = [];
          code = code.replace(varPattern, (match, varName) => {
            const value = vars[varName];
            const idx = placeholders.length;
            const placeholder = `SURGEVAR${idx}X`;
            if (value !== undefined && value !== '') {
              placeholders.push({ type: 'value', text: value, placeholder });
            } else {
              placeholders.push({ type: 'missing', text: match, placeholder });
            }
            return placeholder;
          });

          // Apply syntax highlighting with explicit language
          let highlighted;
          try {
            highlighted = safeHljs.highlight(code, { language: lang }).value;
          } catch (e) {
            highlighted = safeHljs.highlightAuto(code).value;
          }

          // Replace placeholders with styled spans
          // We use a regex to find the placeholder even if hljs wrapped it in tags
          placeholders.forEach((p) => {
            const replacement = p.type === 'value'
              ? `<span class="var-value">${escapeHtml(p.text)}</span>`
              : `<span class="var-missing">${escapeHtml(p.text)}</span>`;
            
            // Try exact match first
            if (highlighted.includes(p.placeholder)) {
              highlighted = highlighted.split(p.placeholder).join(replacement);
            } else {
              // Fallback: look for mangled placeholder (e.g. with hljs tags inside)
              // This is a bit risky but handles cases where hljs splits the identifier
              const mangledRegex = new RegExp(p.placeholder.split('').join('(?:<[^>]+>)*'), 'g');
              highlighted = highlighted.replace(mangledRegex, replacement);
            }
          });
          codeEl.innerHTML = highlighted;
          codeEl.classList.add('hljs');
        }

        // Update step-level code blocks (descendants, not in substeps)
        const stepCodeEls = stepEl.querySelectorAll('.code-block code');
        if (step.codes) {
          stepCodeEls.forEach((codeEl, codeIndex) => {
            if (step.codes[codeIndex]) {
              highlightCodeEl(codeEl, step.codes[codeIndex]);
            }
          });
        }

        // Update substep code blocks
        if (step.substeps) {
          const substepEls = stepEl.querySelectorAll('.substep');
          substepEls.forEach((substepEl, substepIndex) => {
            const substep = step.substeps[substepIndex];
            if (!substep) return;

            // Update substep notes
            const substepNotesEls = substepEl.querySelectorAll('.step-notes:not(.post-notes)');
            if (substep.notes) {
              substepNotesEls.forEach((noteEl, i) => {
                const note = substep.notes[i];
                if (note) {
                  const text = typeof note === 'string' ? note : note.content;
                  noteEl.innerHTML = parseNotesMarkdown(text);
                }
              });
            }

            // Update substep post-notes
            const substepPostNotesEls = substepEl.querySelectorAll('.step-notes.post-notes');
            if (substep.postNotes) {
              substepPostNotesEls.forEach((noteEl, i) => {
                const note = substep.postNotes[i];
                if (note) {
                  const text = typeof note === 'string' ? note : note.content;
                  noteEl.innerHTML = parseNotesMarkdown(text);
                }
              });
            }

            // Update substep code blocks
            const substepCodeEls = substepEl.querySelectorAll('.code-block code');
            if (substep.codes) {
              substepCodeEls.forEach((codeEl, codeIndex) => {
                if (substep.codes[codeIndex]) {
                  highlightCodeEl(codeEl, substep.codes[codeIndex]);
                }
              });
            }
          });
        }
      });
    }

    function updateSelection() {
      document.querySelectorAll('.procedure').forEach((el, i) => {
        el.classList.toggle('selected', i === selectedIndex);
      });
    }

    function copyBlock(el) {
      const code = el.querySelector('code').textContent;
      const substituted = substituteVariables(code).text;
      const procEl = el.closest('.procedure');
      const procIndex = parseInt(procEl.dataset.index);
      const proc = currentResults[procIndex]?.item || currentResults[procIndex];
      const procTitle = proc ? proc.title : 'Unknown Procedure';

      navigator.clipboard.writeText(substituted).then(() => {
        el.classList.add('copied');
        setTimeout(() => el.classList.remove('copied'), 1000);
        showToast('Copied code block!', 'success');
        addToHistory({ label: `Copied code block from: ${procTitle}`, content: substituted });
      });
    }

    function copyCode(btn, procIndex, stepIndex) {
      const proc = currentResults[procIndex]?.item || currentResults[procIndex];
      if (!proc) return;
      const step = proc.steps[stepIndex];

      let content;
      if (step.substeps) {
        // Step with substeps - copy entire section as markdown
        let markdown = `### ${step.title}\n`;
        if (step.notes && step.notes.length) {
          markdown += notesToMarkdown(step.notes) + '\n';
        }
        if (step.codes && step.codes.length) {
          step.codes.forEach(c => {
            markdown += `\`\`\`${c.lang || 'bash'}\n${substituteVariables(c.code).text}\n\`\`\`\n`;
          });
        }
        step.substeps.forEach(ss => {
          markdown += `#### ${ss.title}\n`;
          if (ss.notes && ss.notes.length) {
            markdown += notesToMarkdown(ss.notes) + '\n';
          }
          if (ss.codes && ss.codes.length) {
            ss.codes.forEach(c => {
              markdown += `\`\`\`${c.lang || 'bash'}\n${substituteVariables(c.code).text}\n\`\`\`\n`;
            });
          }
        });
        content = markdown.trim();
      } else {
        // Regular step - just copy code
        content = step.codes && step.codes.length ? step.codes.map(c => substituteVariables(c.code).text).join('\n\n') : '';
      }

      const originalText = btn.textContent;
      navigator.clipboard.writeText(content).then(() => {
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.textContent = originalText;
        }, 1500);
        showToast('Copied step!', 'success');
        addToHistory({ label: `Copied step: ${step.title} (${proc.title})`, content: content });
      });
    }

    function copySubstepCode(btn, procIndex, stepIndex, substepIndex) {
      const proc = currentResults[procIndex]?.item || currentResults[procIndex];
      if (!proc) return;
      const substep = proc.steps[stepIndex].substeps[substepIndex];
      const codes = substep.codes && substep.codes.length ? substep.codes.map(c => substituteVariables(c.code).text).join('\n\n') : '';

      navigator.clipboard.writeText(codes).then(() => {
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.textContent = 'Copy';
        }, 1500);
        showToast('Copied substep!', 'success');
        addToHistory({ label: `Copied substep: ${substep.title} (${proc.title})`, content: codes });
      });
    }

    function copyAll(btn, procIndex) {
      const proc = currentResults[procIndex]?.item || currentResults[procIndex];
      if (!proc) return;

      // Build complete markdown structure
      let markdown = '';

      // Procedure title (H2)
      markdown += `## ${proc.title}\n`;

      // Resources line (if any)
      if (proc.resources && proc.resources.length) {
        markdown += `resources: ${proc.resources.map(r => `[${r.text}](${r.url})`).join(', ')}\n`;
      }

      // Procedure-level notes
      if (proc.notes && proc.notes.length) {
        markdown += '\n' + notesToMarkdown(proc.notes);
      }

      // All steps (including optional and alternative)
      (proc.steps || []).forEach(step => {
          // Step title (H3)
          markdown += `### ${step.title}\n`;

          // Step-level notes
          if (step.notes && step.notes.length) {
            markdown += notesToMarkdown(step.notes) + '\n';
          }

          // Step-level code blocks
          if (step.codes && step.codes.length) {
            step.codes.forEach(c => {
              markdown += `\`\`\`${c.lang || 'bash'}\n${substituteVariables(c.code).text}\n\`\`\`\n`;
            });
          }

          // All substeps (including optional and alternative)
          if (step.substeps) {
            step.substeps.forEach(ss => {
                // Substep title (H4)
                markdown += `#### ${ss.title}\n`;

                // Substep notes
                if (ss.notes && ss.notes.length) {
                  markdown += notesToMarkdown(ss.notes) + '\n';
                }

                // Substep code blocks
                if (ss.codes && ss.codes.length) {
                  ss.codes.forEach(c => {
                    markdown += `\`\`\`${c.lang || 'bash'}\n${substituteVariables(c.code).text}\n\`\`\`\n`;
                  });
                }
              });
          }
        });

      const content = markdown.trim();
      navigator.clipboard.writeText(content).then(() => {
        btn.classList.add('copied');
        btn.textContent = 'Copied!';
        setTimeout(() => {
          btn.classList.remove('copied');
          btn.textContent = 'Copy All';
        }, 1500);
        addToHistory({ label: `Copied entire note: ${proc.title}`, content: content });
      });
    }

    // Search input handler with debounce

    function filterResults(items) {
      return items.filter(item => {
        const proc = item.item || item;
        // Get all toggle tags this procedure has
        const procToggleTags = TOGGLES.filter(toggle => {
          const tagLower = toggle.tag.toLowerCase();
          return proc[tagLower];
        });
        // If procedure has no toggle tags, show it
        if (procToggleTags.length === 0) {
          return true;
        }
        // If procedure has ANY enabled toggle tag, show it (OR logic)
        return procToggleTags.some(toggle => toggleStates[toggle.tag]);
      });
    }

    function performSearch(query) {
      selectedIndex = 0;
      if (!query) {
        const filtered = filterResults(commands);
        render(filtered.slice(0, MAX_RESULTS), filtered.length);
        return;
      }
      const results = filterResults(fuse.search(query));
      render(results.slice(0, MAX_RESULTS), results.length);
    }

    document.getElementById('search').addEventListener('input', (e) => {
      const query = e.target.value.trim();
      clearTimeout(searchTimeout);
      searchTimeout = setTimeout(() => performSearch(query), DEBOUNCE_MS);
    });

    // Keyboard navigation
    document.addEventListener('keydown', (e) => {
      const procedures = document.querySelectorAll('.procedure');

      if (e.key === 'ArrowDown') {
        e.preventDefault();
        document.getElementById('search').blur();
        selectedIndex = Math.min(selectedIndex + 1, procedures.length - 1);
        updateSelection();
        procedures[selectedIndex]?.scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'ArrowUp') {
        e.preventDefault();
        document.getElementById('search').blur();
        selectedIndex = Math.max(selectedIndex - 1, 0);
        updateSelection();
        procedures[selectedIndex]?.scrollIntoView({ block: 'nearest' });
      } else if (e.key === 'Enter' && document.activeElement.tagName !== 'TEXTAREA') {
        e.preventDefault();
        toggleProcedure(selectedIndex);
      } else if (e.key === 'Escape') {
        document.getElementById('search').value = '';
        document.getElementById('search').focus();
        selectedIndex = 0;
        const filtered = filterResults(commands);
        render(filtered.slice(0, MAX_RESULTS), filtered.length);
      } else if (e.key === 'c' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        const btn = document.querySelector(`.procedure[data-index="${selectedIndex}"] .copy-all-btn`);
        if (btn) btn.click();
      } else if (e.key === 'w' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        toggleWrap();
      } else if (e.key === 'v' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        toggleVarPanel();
      } else if (e.key === 'h' && document.activeElement.tagName !== 'INPUT') {
        e.preventDefault();
        toggleHistoryPanel();
      }
    });

