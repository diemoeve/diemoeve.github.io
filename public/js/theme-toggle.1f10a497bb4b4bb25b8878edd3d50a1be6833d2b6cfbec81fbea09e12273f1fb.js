(() => {
  // <stdin>
  var storageKey = "theme";
  var classList = document.documentElement.classList;
  var applyTheme = (theme) => {
    if (theme === "dark") {
      classList.add("dark");
    } else {
      classList.remove("dark");
    }
  };
  var persistTheme = (theme) => {
    try {
      window.localStorage.setItem(storageKey, theme);
    } catch (err) {
    }
  };
  var updateButtonState = (button, theme) => {
    button.dataset.theme = theme;
    button.setAttribute("aria-label", theme === "dark" ? "Switch to light mode" : "Switch to dark mode");
  };
  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle");
    if (!button) {
      return;
    }
    const initialTheme = classList.contains("dark") ? "dark" : "light";
    updateButtonState(button, initialTheme);
    button.addEventListener("click", () => {
      const nextTheme = classList.contains("dark") ? "light" : "dark";
      applyTheme(nextTheme);
      updateButtonState(button, nextTheme);
      persistTheme(nextTheme);
    });
  });
})();
