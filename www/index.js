import * as wasm from "pem-viewer";

function run() {
    var input = document.getElementById("input");
    wasm.parse(input.value);
}

run()

window.run = run
