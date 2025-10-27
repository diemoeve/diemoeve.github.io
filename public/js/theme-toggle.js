const storageKey = 'theme';
const root = document.documentElement;

const setTheme = (mode) => {
  const isDark = mode === 'dark';
  root.classList.toggle('dark', isDark);
  try {
    localStorage.setItem(storageKey, isDark ? 'dark' : 'light');
  } catch (err) {
    /* ignore storage errors */
  }
  const toggle = document.getElementById('theme-toggle');
  if (toggle) {
    toggle.setAttribute('aria-pressed', String(isDark));
    toggle.setAttribute('aria-label', isDark ? 'Switch to light mode' : 'Switch to dark mode');
  }
};

const initThemeToggle = () => {
  const button = document.getElementById('theme-toggle');
  if (!button) {
    return;
  }

  const startDark = root.classList.contains('dark');
  button.setAttribute('aria-pressed', String(startDark));
  button.setAttribute('aria-label', startDark ? 'Switch to light mode' : 'Switch to dark mode');

  button.addEventListener('click', () => {
    const nextMode = root.classList.contains('dark') ? 'light' : 'dark';
    setTheme(nextMode);
  });
};

document.addEventListener('DOMContentLoaded', initThemeToggle);
