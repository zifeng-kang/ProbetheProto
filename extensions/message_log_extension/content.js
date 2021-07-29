//console.log('Logging message received in ', window.location.href);
var sc = document.createElement('script');
sc.textContent = '(' + (function() {
        window.addEventListener('message', (event) => {
                msg = event.data;
                if (typeof msg === 'object' && msg !== undefined) {
                        msg = JSON.stringify(msg);
                }
                //var is_object = ( typeof msg === 'object' )
                console.log('Received message: ' + msg + ' Received from: ' + event.origin + ' Receiver: ' + window.location.href);
        });
}).toString() + ')()';
document.body.appendChild(sc);
