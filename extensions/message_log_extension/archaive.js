console.log('Logging message received in ', window.location.href);
var sc = document.createElement('script');
sc.textContent = '(' + (function() {
    window.addEventListener('message', (event) => {
        msg = event.data;
        if (typeof msg === 'object' && msg !== null) {
            msg = JSON.stringify(msg);
        }
            console.log('Received message: ' + msg);
        console.log('Received from: ' + event.origin);
    });
}).toString() + ')()';
document.body.appendChild(sc);
