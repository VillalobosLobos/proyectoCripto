let correos = [];

function agregarCorreo() {
    const input = document.getElementById("correo_input");
    const correo = input.value.trim();

    if (correo && !correos.includes(correo)) {
        correos.push(correo);
        actualizarLista();
    }

    input.value = "";
    document.getElementById("correos_autorizados").value = correos.join(",");
}

function actualizarLista() {
    const lista = document.getElementById("lista_correos");
    lista.innerHTML = "";
    correos.forEach(correo => {
        const li = document.createElement("li");
        li.textContent = correo;
        lista.appendChild(li);
    });
}
