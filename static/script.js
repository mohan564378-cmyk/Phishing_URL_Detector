// ==========================================
// URL VALIDATION
// ==========================================

function validateURL() {

    const input =
        document.getElementById("urlInput");

    const button =
        document.getElementById("scanButton");

    const loading =
        document.getElementById("loadingMessage");

    const url =
        input.value.trim();


    // Check empty input
    if (url === "") {

        alert("Please enter a URL.");

        return false;
    }


    // Check URL format
    try {

        const parsedURL = new URL(url);

        if (
            parsedURL.protocol !== "http:" &&
            parsedURL.protocol !== "https:"
        ) {

            alert(
                "Please enter a URL beginning with http:// or https://"
            );

            return false;
        }

    } catch (error) {

        alert("Please enter a valid URL.");

        return false;
    }


    // Show loading message
    if (loading) {

        loading.style.display = "block";
    }


    // Disable scan button
    if (button) {

        button.disabled = true;

        button.innerHTML =
            "⏳ Scanning...";
    }


    return true;
}



// ==========================================
// USE EXAMPLE URL
// ==========================================

function useExampleURL() {

    const input =
        document.getElementById("urlInput");


    if (input) {

        input.value =
            "https://example.com";

        input.focus();
    }

}



// ==========================================
// HIDE LOADING MESSAGE WHEN PAGE LOADS
// ==========================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const loading =
            document.getElementById("loadingMessage");

        if (loading) {

            loading.style.display = "none";
        }

    }
);