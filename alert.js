function showAlert(level, message) {
    const container = document.createElement("div");
    container.className = `tb-alert tb-${level}`;

    let icon = "../ui-icons/alert.png";
    if (level === "high") icon = "../ui-icons/firewall.png";
    if (level === "medium") icon = "../ui-icons/radar.png";

    container.innerHTML = `
        <img src="${icon}" class="alert-icon">
        <div class="alert-text">${message}</div>
        <button class="alert-close">OK</button>
    `;

    document.body.appendChild(container);

    container.querySelector(".alert-close").onclick = () => {
        container.remove();
    };
}
