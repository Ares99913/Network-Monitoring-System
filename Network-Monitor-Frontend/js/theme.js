function toggleTheme() {
    const body = document.body;
    const icon = document.getElementById("themeIcon");

    if (body.getAttribute("data-theme") === "light") {
        body.removeAttribute("data-theme");
        icon.className = "bi bi-moon-stars-fill";
        localStorage.setItem("theme", "dark");
    } else {
        body.setAttribute("data-theme", "light");
        icon.className = "bi bi-sun-fill";
        localStorage.setItem("theme", "light");
    }
}

window.addEventListener("DOMContentLoaded", () => {
    const savedTheme = localStorage.getItem("theme");
    const icon = document.getElementById("themeIcon");

    if (savedTheme === "light") {
        document.body.setAttribute("data-theme", "light");
        icon.className = "bi bi-sun-fill";
    }
});