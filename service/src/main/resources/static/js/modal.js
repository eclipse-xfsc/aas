function closeModal() {
    const modal = document.getElementById("modal")
    if (modal.classList.contains("show")) {
        modal.classList.remove("show");
        modal.classList.add("hide")
    }
}