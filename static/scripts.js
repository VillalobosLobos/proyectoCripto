function agregarCorreo() {
    const input = document.getElementById('correo_input');
    const email = input.value.trim();
    if (!email) return alert('Por favor escribe un correo válido');

    // Evitar duplicados
    const listaCorreos = Array.from(document.querySelectorAll('#correos_ocultos input')).map(i => i.value);
    if (listaCorreos.includes(email)) return alert('Correo ya agregado');

    // Agregar visualmente en la lista
    const li = document.createElement('li');
    li.textContent = email + ' ';
    const btnEliminar = document.createElement('button');
    btnEliminar.textContent = 'Eliminar';
    btnEliminar.type = 'button';
    btnEliminar.onclick = () => {
        li.remove();
        inputOculto.remove();
    };
    li.appendChild(btnEliminar);
    document.getElementById('lista_correos').appendChild(li);

    // Agregar input oculto con name="emails[]" para que se envíe al backend
    const inputOculto = document.createElement('input');
    inputOculto.type = 'hidden';
    inputOculto.name = 'emails[]';
    inputOculto.value = email;
    document.getElementById('correos_ocultos').appendChild(inputOculto);

    input.value = '';
}
