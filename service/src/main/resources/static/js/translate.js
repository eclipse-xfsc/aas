
function translate(language) {

    let params = new URLSearchParams(window.location.search)
    params.set('lang',language)
    window.location.search = params.toString()

}

document.getElementById("Deutsch").addEventListener("click", () => translate("de"));
document.getElementById("English").addEventListener("click", () => translate("en"));
document.getElementById("Français").addEventListener("click", () => translate("fr"));
document.getElementById("Русский").addEventListener("click", () => translate("ru"));
document.getElementById("Slovensky").addEventListener("click", () => translate("sk"));
