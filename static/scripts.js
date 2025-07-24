var socket = io();

function sendCommand() {
    var command = document.getElementById("command").value;
    var method = document.getElementById("method").value;
    socket.emit("send_command", { command: command, method: method });
}

socket.on("response", function(data) {
    document.getElementById("response").innerText = data;
});