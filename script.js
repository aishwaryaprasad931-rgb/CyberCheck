
// PASSWORD STRENGTH CHECKER

const passwordInput = document.getElementById("passwordInput");
const strengthBar = document.getElementById("strengthBar");
const strengthText = document.getElementById("strengthText");
const checks = document.querySelectorAll("#passwordChecks li");

const rules = {
    length: value => value.length >= 8,
    upper: value => /[A-Z]/.test(value),
    lower: value => /[a-z]/.test(value),
    number: value => /[0-9]/.test(value),
    special: value => /[^A-Za-z0-9]/.test(value)
};

passwordInput.addEventListener("input", () => {
    const password = passwordInput.value;
    let score = 0;

    checks.forEach(item => {
        const rule = item.dataset.check;
        const passed = rules[rule](password);

        item.classList.toggle("valid", passed);

        if (passed) score++;
    });

    strengthBar.style.width = (score * 20) + "%";

    const levels = [
        "Very Weak",
        "Weak",
        "Fair",
        "Good",
        "Strong",
        "Very Strong"
    ];

    strengthText.textContent = password
        ? levels[score]
        : "Waiting for password...";

    const colors = [
        "#e74c3c",
        "#e74c3c",
        "#f39c12",
        "#f1c40f",
        "#2ecc71",
        "#39d5bd"
    ];

    strengthBar.style.background = colors[score];
});

document.getElementById("togglePassword").addEventListener("click", () => {
    const button = document.getElementById("togglePassword");

    if (passwordInput.type === "password") {
        passwordInput.type = "text";
        button.textContent = "Hide";
    } else {
        passwordInput.type = "password";
        button.textContent = "Show";
    }
});


// SUSPICIOUS URL ANALYZER

const urlInput = document.getElementById("urlInput");
const scanBtn = document.getElementById("scanBtn");
const urlResult = document.getElementById("urlResult");

scanBtn.addEventListener("click", analyzeURL);

urlInput.addEventListener("keydown", event => {
    if (event.key === "Enter") analyzeURL();
});

function analyzeURL() {
    const input = urlInput.value.trim();

    if (!input) {
        alert("Please enter a URL!");
        return;
    }

    let url;

    try {
        const normalized = /^https?:\/\//i.test(input)
            ? input
            : "https://" + input;

        url = new URL(normalized);

        if (!["http:", "https:"].includes(url.protocol) ||
            !url.hostname.includes(".") ||
            !/^[a-z0-9.-]+$/i.test(url.hostname)) {
            throw new Error("Invalid website address");
        }
    } catch {
        alert("Please enter a valid website URL.");
        return;
    }

    const host = url.hostname.toLowerCase();
    const fullURL = input.toLowerCase();

    let findings = [];
    let risk = 0;

    // Check HTTPS
    if (url.protocol !== "https:") {
        findings.push("⚠️ Website does not use HTTPS.");
        risk += 2;
    } else {
        findings.push("✓ Website uses HTTPS.");
    }

    // Check IP address
    const isIP = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);

    if (isIP) {
        findings.push("⚠️ URL uses an IP address instead of a domain name.");
        risk += 2;
    }

    // Check @ symbol
    if (url.username || url.password || fullURL.includes("@")) {
        findings.push("⚠️ URL contains an @ symbol or embedded credentials.");
        risk += 3;
    }

    // Check suspicious keywords
    const suspiciousWords = [
        "login", "verify", "update",
        "secure", "account", "bank",
        "free", "gift", "password"
    ];

    const foundWords = suspiciousWords.filter(word =>
        host.split(".").some(part => part === word) ||
        url.pathname.toLowerCase().includes(word)
    );

    if (foundWords.length > 0) {
        findings.push("⚠️ Contains potentially suspicious words: " +
            foundWords.join(", "));
        risk += 1;
    }

    // Check long hostname
    if (host.length > 30) {
        findings.push("⚠️ Unusually long domain name.");
        risk += 1;
    }

    // Check hyphens
    if ((host.match(/-/g) || []).length >= 2) {
        findings.push("⚠️ Domain contains multiple hyphens.");
        risk += 1;
    }

    // Check punycode
    if (host.includes("xn--")) {
        findings.push("⚠️ Domain uses internationalized encoding (punycode).");
        risk += 2;
    }

    // Check subdomains
    if (host.split(".").length > 3) {
        findings.push("⚠️ Multiple subdomains detected.");
        risk += 1;
    }

    if (findings.length === 0) {
        findings.push("✓ No obvious warning signs detected by these checks.");
    }

    const status = document.getElementById("urlStatus");
    const description = document.getElementById("urlDescription");
    const findingsList = document.getElementById("urlFindings");

    if (risk >= 4) {
        status.textContent = "⚠️ High Risk Indicators";
        status.style.color = "#e74c3c";
        description.textContent =
            "Several suspicious characteristics were detected. Avoid interacting with this link until independently verified.";
    } else if (risk >= 2) {
        status.textContent = "⚠️ Caution Required";
        status.style.color = "#f39c12";
        description.textContent =
            "Some warning signs were detected. Verify the website before proceeding.";
    } else {
        status.textContent = "✓ No Major Warning Signs";
        status.style.color = "#39d5bd";
        description.textContent =
            "Few warning signs were detected. This does not guarantee that the website is safe.";
    }

    findingsList.innerHTML = "";

    findings.forEach(item => {
        const li = document.createElement("li");
        li.textContent = item;
        findingsList.appendChild(li);
    });

    urlResult.classList.remove("hidden");
}
